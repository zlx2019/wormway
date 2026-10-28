//! Integration tests of `Server` with a line echo service.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::runtime::Handle;
use zora_core::config::{Config, Listener, Name, Protocol};
use zora_runtime::{
    ApplyError, BoxError, BoxFuture, Connection, Server, Service, ServiceFactory, Services,
    Shutdown,
};

/// Answers every line with `<generation> <draining> <line>`. It ignores the shutdown signal, so
/// connections only end when the client leaves or the shutdown timeout closes them.
struct Echo {
    /// Number of the service in creation order, starting at 1.
    generation: usize,
}

impl Service for Echo {
    /// Echoes lines until the client closes the connection.
    fn serve(self: Arc<Self>, conn: Connection, shutdown: Shutdown) -> BoxFuture<'static> {
        Box::pin(async move {
            let (read, mut write) = conn.stream.into_split();
            let mut lines = BufReader::new(read).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let reply = format!("{} {} {line}\n", self.generation, *shutdown.borrow());
                if write.write_all(reply.as_bytes()).await.is_err() {
                    break;
                }
            }
        })
    }
}

/// Builds `Echo` services and counts them.
#[derive(Default)]
struct EchoFactory {
    /// Services created so far.
    created: Arc<AtomicUsize>,
}

impl ServiceFactory for EchoFactory {
    /// Creates the next generation.
    fn create(&self, _: &Name, _: &Listener) -> Result<Arc<dyn Service>, BoxError> {
        let generation = self.created.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(Arc::new(Echo { generation }))
    }
}

/// A listener on any free loopback port.
const WEB: &str = "[listeners.web]\nlisten = [\"127.0.0.1:0\"]\nprotocol = \"http\"\n";
/// A second listener on any free loopback port.
const API: &str = "[listeners.api]\nlisten = [\"127.0.0.1:0\"]\nprotocol = \"http\"\n";

/// Parses a configuration, adding `version = 1` in front.
fn parse(text: &str) -> Config {
    Config::from_toml(&format!("version = 1\n{text}")).expect("valid configuration")
}

/// Starts a server on the test runtime with echo services for `http` listeners, and returns it
/// with the number of services created.
fn start(text: &str) -> (Server, Arc<AtomicUsize>) {
    let factory = EchoFactory::default();
    let created = factory.created.clone();
    let mut services = Services::new();
    services.register(Protocol::Http, factory);
    match Server::start(Handle::current(), services, parse(text)) {
        Ok(server) => (server, created),
        Err(error) => panic!("cannot start: {error}"),
    }
}

/// The first bound address of `listener`.
fn addr(server: &Server, listener: &str) -> SocketAddr {
    server.listeners()[listener][0]
}

/// A free loopback port, released before it is returned.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    listener.local_addr().expect("local address").port()
}

/// Whether connecting to `addr` is refused within two seconds. Closing a socket happens in its
/// accept loop, shortly after the server asked for it.
async fn refused(addr: SocketAddr) -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if TcpStream::connect(addr).await.is_err() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    false
}

/// A test client that sends lines and reads the replies.
struct Client {
    /// Replies from the server.
    lines: Lines<BufReader<OwnedReadHalf>>,
    /// Requests to the server.
    write: OwnedWriteHalf,
}

impl Client {
    /// Connects to `addr`.
    async fn connect(addr: SocketAddr) -> Self {
        let (read, write) = TcpStream::connect(addr)
            .await
            .expect("connect")
            .into_split();
        Self {
            lines: BufReader::new(read).lines(),
            write,
        }
    }

    /// Sends `line` and returns the reply, or `None` if the server closed the connection.
    async fn ask(&mut self, line: &str) -> Option<String> {
        self.write
            .write_all(format!("{line}\n").as_bytes())
            .await
            .ok()?;
        let reply = tokio::time::timeout(Duration::from_secs(5), self.lines.next_line());
        reply.await.expect("reply in time").ok().flatten()
    }
}

/// Connections reach the service of their listener.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serves_connections() {
    let (server, _) = start(WEB);
    let mut client = Client::connect(addr(&server, "web")).await;
    assert_eq!(client.ask("ping").await.as_deref(), Some("1 false ping"));
    assert_eq!(server.snapshot().version, 1);
}

/// Unchanged listeners keep their service and their connections are not told to drain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leaves_unchanged_listeners_alone() {
    let (server, created) = start(WEB);
    let web_addr = addr(&server, "web");
    let mut web = Client::connect(web_addr).await;

    let snapshot = server.apply(parse(&format!("{WEB}{API}"))).expect("apply");
    assert_eq!(snapshot.version, 2);
    // Even on port 0 the socket stays, so the address does not change.
    assert_eq!(addr(&server, "web"), web_addr);
    assert_eq!(web.ask("ping").await.as_deref(), Some("1 false ping"));
    let mut api = Client::connect(addr(&server, "api")).await;
    assert_eq!(api.ask("ping").await.as_deref(), Some("2 false ping"));
    assert_eq!(created.load(Ordering::SeqCst), 2);
}

/// A changed listener gets a new service; its old connections stay with the draining one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebuilds_changed_listeners() {
    let (server, _) = start(WEB);
    let old_addr = addr(&server, "web");
    let mut old = Client::connect(old_addr).await;
    assert_eq!(old.ask("ping").await.as_deref(), Some("1 false ping"));

    // Adding TLS changes the listener. Port 0 then binds a new port and closes the old one.
    let with_tls = format!(
        "{WEB}tls = {{ certificates = [\"test\"] }}\n[certificates.test]\ncert = \"t.crt\"\nkey = \"t.key\"\n"
    );
    server.apply(parse(&with_tls)).expect("apply");
    assert_eq!(old.ask("ping").await.as_deref(), Some("1 true ping"));
    let mut new = Client::connect(addr(&server, "web")).await;
    assert_eq!(new.ask("ping").await.as_deref(), Some("2 false ping"));
    assert!(refused(old_addr).await);
}

/// A fixed port moves to a renamed listener without closing its socket. A new bind would fail
/// while the old socket is still open, so success shows that the socket was handed over.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hands_sockets_over_to_renamed_listeners() {
    let port = free_port();
    let listener = |name: &str| {
        format!("[listeners.{name}]\nlisten = [\"127.0.0.1:{port}\"]\nprotocol = \"http\"\n")
    };
    let (server, _) = start(&listener("web"));
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let mut old = Client::connect(addr).await;
    assert_eq!(old.ask("ping").await.as_deref(), Some("1 false ping"));

    server.apply(parse(&listener("site"))).expect("apply");
    let mut new = Client::connect(addr).await;
    assert_eq!(new.ask("ping").await.as_deref(), Some("2 false ping"));
    assert_eq!(old.ask("ping").await.as_deref(), Some("1 true ping"));
    assert_eq!(
        server.listeners().into_iter().collect::<Vec<_>>(),
        [("site".parse().unwrap(), vec![addr])]
    );
}

/// A removed listener closes its socket and drains its connections.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closes_removed_listeners() {
    let (server, _) = start(WEB);
    let web = addr(&server, "web");
    let mut old = Client::connect(web).await;
    // Make sure the connection was accepted: closing a socket resets the ones still queued.
    assert_eq!(old.ask("ping").await.as_deref(), Some("1 false ping"));

    server.apply(parse("")).expect("apply");
    assert!(server.listeners().is_empty());
    assert!(refused(web).await);
    assert_eq!(old.ask("ping").await.as_deref(), Some("1 true ping"));
}

/// When an address cannot be bound, the configuration in effect stays as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keeps_running_configuration_on_bind_error() {
    let (server, _) = start(WEB);
    let mut web = Client::connect(addr(&server, "web")).await;
    let blocker = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let taken = blocker.local_addr().expect("local address");

    let api = format!("[listeners.api]\nlisten = [\"{taken}\"]\nprotocol = \"http\"\n");
    let error = server.apply(parse(&format!("{WEB}{api}"))).unwrap_err();
    assert!(
        matches!(&error, ApplyError::Bind { listener, addr, .. } if listener.as_str() == "api" && *addr == taken),
        "{error:?}"
    );
    assert_eq!(server.snapshot().version, 1);
    assert_eq!(server.listeners().len(), 1);
    assert_eq!(web.ask("ping").await.as_deref(), Some("1 false ping"));
}

/// Invalid configurations are rejected before anything changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_invalid_configurations() {
    let (server, _) = start(WEB);
    let mut invalid = parse(WEB);
    invalid.listeners.get_mut("web").unwrap().listen.clear();
    assert!(matches!(server.apply(invalid), Err(ApplyError::Config(_))));
    assert_eq!(server.snapshot().version, 1);
}

/// A listener whose protocol has no service factory is rejected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_protocols_without_a_service() {
    let Err(error) = Server::start(Handle::current(), Services::new(), parse(WEB)) else {
        panic!("a listener without a service must be rejected");
    };
    assert_eq!(
        error.to_string(),
        "listener web: protocol http is not available in this build"
    );
}

/// Dropping the server without a shutdown still closes its sockets.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_server_closes_its_sockets() {
    let (server, _) = start(WEB);
    let web = addr(&server, "web");
    drop(server);
    assert!(refused(web).await);
}

/// Shutdown waits for open connections until the timeout, then closes them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_closes_connections_after_the_timeout() {
    let (server, _) = start(&format!("[server]\nshutdown_timeout = \"300ms\"\n{WEB}"));
    let web = addr(&server, "web");
    let mut client = Client::connect(web).await;
    assert!(client.ask("ping").await.is_some());

    let started = Instant::now();
    server.shutdown().await;
    let took = started.elapsed();
    assert!(took >= Duration::from_millis(300), "took {took:?}");
    assert!(took < Duration::from_secs(2), "took {took:?}");
    assert_eq!(client.ask("ping").await, None);
    assert!(refused(web).await);
}

/// Shutdown ends as soon as the last connection does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_ends_with_the_last_connection() {
    let (server, _) = start(&format!("[server]\nshutdown_timeout = \"10s\"\n{WEB}"));
    let mut client = Client::connect(addr(&server, "web")).await;
    assert!(client.ask("ping").await.is_some());

    let started = Instant::now();
    let leave = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        drop(client);
    };
    tokio::join!(server.shutdown(), leave);
    assert!(
        started.elapsed() < Duration::from_secs(2),
        "took {:?}",
        started.elapsed()
    );
}
