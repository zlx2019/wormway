//! Integration tests of `Server` with a line echo service and an engine that records its calls.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines};
use tokio::net::TcpStream;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::runtime::Handle;
use wormway_core::config::{Config, ConfigError, Issue, Listener, Name, Protocol};
use wormway_runtime::{
    ApplyError, BoxError, BoxFuture, Connection, Engine, Server, Service, ServiceFactory, Services,
    Shutdown, Staged,
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

/// Logs the listener names of every configuration it prepares and commits. It refuses
/// configurations with a listener named `refused`.
#[derive(Clone, Default)]
struct Recorder {
    /// `prepare <names>` and `commit <names>` lines, in call order.
    log: Arc<Mutex<Vec<String>>>,
}

impl Recorder {
    /// Returns the lines logged so far.
    fn lines(&self) -> Vec<String> {
        self.log.lock().expect("log").clone()
    }

    /// Appends a line.
    fn record(&self, line: String) {
        self.log.lock().expect("log").push(line);
    }
}

impl Engine for Recorder {
    /// Logs the listener names, or refuses the configuration.
    fn prepare<'a>(
        &'a self,
        config: &'a Config,
    ) -> BoxFuture<'a, Result<Box<dyn Staged>, Vec<Issue>>> {
        Box::pin(async move {
            if config.listeners.contains_key("refused") {
                return Err(vec![Issue {
                    path: "listeners.refused".to_owned(),
                    message: "refused by the recorder".to_owned(),
                }]);
            }
            let names: Vec<&str> = config.listeners.keys().map(Name::as_str).collect();
            let names = names.join(",");
            self.record(format!("prepare {names}"));
            let staged: Box<dyn Staged> = Box::new(Recorded {
                recorder: self.clone(),
                names,
            });
            Ok(staged)
        })
    }
}

/// What the recorder prepared.
struct Recorded {
    /// Where to log the commit.
    recorder: Recorder,
    /// Listener names of the configuration.
    names: String,
}

impl Staged for Recorded {
    /// Logs the commit.
    fn commit(self: Box<Self>) {
        self.recorder.record(format!("commit {}", self.names));
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
async fn start(text: &str) -> (Server, Arc<AtomicUsize>) {
    let factory = EchoFactory::default();
    let created = factory.created.clone();
    let mut services = Services::new();
    services.register(Protocol::Http, factory);
    match Server::start(Handle::current(), services, parse(text)).await {
        Ok(server) => (server, created),
        Err(error) => panic!("cannot start: {error}"),
    }
}

/// Starts a server like [`start`], with `recorder` as its engine.
async fn start_recorded(text: &str, recorder: &Recorder) -> Server {
    let mut services = Services::new();
    services.register(Protocol::Http, EchoFactory::default());
    services.add_engine(recorder.clone());
    match Server::start(Handle::current(), services, parse(text)).await {
        Ok(server) => server,
        Err(error) => panic!("cannot start: {error}"),
    }
}

/// The first bound address of `listener`.
async fn addr(server: &Server, listener: &str) -> SocketAddr {
    server.listeners().await[listener][0]
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
    let (server, _) = start(WEB).await;
    let mut client = Client::connect(addr(&server, "web").await).await;
    assert_eq!(client.ask("ping").await.as_deref(), Some("1 false ping"));
    assert_eq!(server.snapshot().version, 1);
}

/// Unchanged listeners keep their service and their connections are not told to drain.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leaves_unchanged_listeners_alone() {
    let (server, created) = start(WEB).await;
    let web_addr = addr(&server, "web").await;
    let mut web = Client::connect(web_addr).await;

    let snapshot = server
        .apply(parse(&format!("{WEB}{API}")))
        .await
        .expect("apply");
    assert_eq!(snapshot.version, 2);
    // Even on port 0 the socket stays, so the address does not change.
    assert_eq!(addr(&server, "web").await, web_addr);
    assert_eq!(web.ask("ping").await.as_deref(), Some("1 false ping"));
    let mut api = Client::connect(addr(&server, "api").await).await;
    assert_eq!(api.ask("ping").await.as_deref(), Some("2 false ping"));
    assert_eq!(created.load(Ordering::SeqCst), 2);
}

/// A changed listener gets a new service; its old connections stay with the draining one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebuilds_changed_listeners() {
    let (server, _) = start(WEB).await;
    let old_addr = addr(&server, "web").await;
    let mut old = Client::connect(old_addr).await;
    assert_eq!(old.ask("ping").await.as_deref(), Some("1 false ping"));

    // Adding TLS changes the listener. Port 0 then binds a new port and closes the old one.
    let with_tls = format!(
        "{WEB}tls = {{ certificates = [\"test\"] }}\n[certificates.test]\ncert = \"t.crt\"\nkey = \"t.key\"\n"
    );
    server.apply(parse(&with_tls)).await.expect("apply");
    assert_eq!(old.ask("ping").await.as_deref(), Some("1 true ping"));
    let mut new = Client::connect(addr(&server, "web").await).await;
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
    let (server, _) = start(&listener("web")).await;
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    let mut old = Client::connect(addr).await;
    assert_eq!(old.ask("ping").await.as_deref(), Some("1 false ping"));

    server.apply(parse(&listener("site"))).await.expect("apply");
    let mut new = Client::connect(addr).await;
    assert_eq!(new.ask("ping").await.as_deref(), Some("2 false ping"));
    assert_eq!(old.ask("ping").await.as_deref(), Some("1 true ping"));
    assert_eq!(
        server.listeners().await.into_iter().collect::<Vec<_>>(),
        [("site".parse().unwrap(), vec![addr])]
    );
}

/// A removed listener closes its socket and drains its connections.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closes_removed_listeners() {
    let (server, _) = start(WEB).await;
    let web = addr(&server, "web").await;
    let mut old = Client::connect(web).await;
    // Make sure the connection was accepted: closing a socket resets the ones still queued.
    assert_eq!(old.ask("ping").await.as_deref(), Some("1 false ping"));

    server.apply(parse("")).await.expect("apply");
    assert!(server.listeners().await.is_empty());
    assert!(refused(web).await);
    assert_eq!(old.ask("ping").await.as_deref(), Some("1 true ping"));
}

/// When an address cannot be bound, the configuration in effect stays as it was.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keeps_running_configuration_on_bind_error() {
    let (server, _) = start(WEB).await;
    let mut web = Client::connect(addr(&server, "web").await).await;
    let blocker = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let taken = blocker.local_addr().expect("local address");

    let api = format!("[listeners.api]\nlisten = [\"{taken}\"]\nprotocol = \"http\"\n");
    let error = server
        .apply(parse(&format!("{WEB}{api}")))
        .await
        .unwrap_err();
    assert!(
        matches!(&error, ApplyError::Bind { listener, addr, .. } if listener.as_str() == "api" && *addr == taken),
        "{error:?}"
    );
    assert_eq!(server.snapshot().version, 1);
    assert_eq!(server.listeners().await.len(), 1);
    assert_eq!(web.ask("ping").await.as_deref(), Some("1 false ping"));
}

/// Invalid configurations are rejected before anything changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_invalid_configurations() {
    let (server, _) = start(WEB).await;
    let mut invalid = parse(WEB);
    invalid.listeners.get_mut("web").unwrap().listen.clear();
    assert!(matches!(
        server.apply(invalid).await,
        Err(ApplyError::Config(_))
    ));
    assert_eq!(server.snapshot().version, 1);
}

/// A listener whose protocol has no service factory is rejected.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rejects_protocols_without_a_service() {
    let Err(error) = Server::start(Handle::current(), Services::new(), parse(WEB)).await else {
        panic!("a listener without a service must be rejected");
    };
    assert_eq!(
        error.to_string(),
        "listener web: protocol http is not available in this build"
    );
}

/// A prepared change that is dropped instead of committed leaves everything as it was, and
/// other changes wait while a prepared one is pending.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn discards_dropped_preparations() {
    let (server, created) = start(WEB).await;
    let prepared = server
        .prepare(parse(&format!("{WEB}{API}")))
        .await
        .expect("prepare");
    let waiting = tokio::time::timeout(
        Duration::from_millis(100),
        server.apply(parse(&format!("{WEB}{API}"))),
    );
    assert!(
        waiting.await.is_err(),
        "a second change ran while one was pending"
    );

    drop(prepared);
    assert_eq!(server.snapshot().version, 1);
    assert_eq!(server.listeners().await.len(), 1);
    // The service built for `api` was dropped with the preparation.
    assert_eq!(created.load(Ordering::SeqCst), 2);
    server
        .apply(parse(&format!("{WEB}{API}")))
        .await
        .expect("apply");
    assert_eq!(server.snapshot().version, 2);
}

/// After a shutdown no change is accepted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refuses_changes_after_shutdown() {
    let (server, _) = start(WEB).await;
    server.shutdown().await;
    let error = server.apply(parse(WEB)).await.unwrap_err();
    assert!(matches!(error, ApplyError::ShuttingDown), "{error:?}");
}

/// Dropping the server without a shutdown still closes its sockets.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_the_server_closes_its_sockets() {
    let (server, _) = start(WEB).await;
    let web = addr(&server, "web").await;
    drop(server);
    assert!(refused(web).await);
}

/// Shutdown waits for open connections until the timeout, then closes them.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_closes_connections_after_the_timeout() {
    let (server, _) = start(&format!("[server]\nshutdown_timeout = \"300ms\"\n{WEB}")).await;
    let web = addr(&server, "web").await;
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
    let (server, _) = start(&format!("[server]\nshutdown_timeout = \"10s\"\n{WEB}")).await;
    let mut client = Client::connect(addr(&server, "web").await).await;
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

/// Engines prepare and commit with the start and with every change.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commits_engines_with_each_change() {
    let recorder = Recorder::default();
    let server = start_recorded(WEB, &recorder).await;
    server
        .apply(parse(&format!("{WEB}{API}")))
        .await
        .expect("apply");
    assert_eq!(
        recorder.lines(),
        [
            "prepare web",
            "commit web",
            "prepare api,web",
            "commit api,web"
        ]
    );
}

/// A problem found by an engine rejects the change with the path of its setting, and a dropped
/// preparation is never committed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engines_can_reject_changes() {
    let recorder = Recorder::default();
    let server = start_recorded(WEB, &recorder).await;
    let refused = "[listeners.refused]\nlisten = [\"127.0.0.1:0\"]\nprotocol = \"http\"\n";
    match server.apply(parse(&format!("{WEB}{refused}"))).await {
        Err(ApplyError::Config(ConfigError::Invalid(issues))) => {
            assert_eq!(issues.len(), 1);
            assert_eq!(issues[0].path, "listeners.refused");
        }
        other => panic!("expected the engine to refuse, got {other:?}"),
    }
    assert_eq!(server.listeners().await.len(), 1);
    assert_eq!(server.snapshot().version, 1);

    let prepared = server
        .prepare(parse(&format!("{WEB}{API}")))
        .await
        .expect("prepare");
    drop(prepared);
    assert_eq!(
        recorder.lines(),
        ["prepare web", "commit web", "prepare api,web"]
    );
}

/// Applying the configuration in effect again prepares the engines again and leaves unchanged
/// listeners alone. A change committed while it waits is what it applies, not the older one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reapplies_the_newest_configuration() {
    let recorder = Recorder::default();
    let server = Arc::new(start_recorded(WEB, &recorder).await);
    let web = addr(&server, "web").await;
    let snapshot = server.reapply().await.expect("reapply");
    assert_eq!(snapshot.version, 2);
    assert_eq!(addr(&server, "web").await, web);

    let prepared = server
        .prepare(parse(&format!("{WEB}{API}")))
        .await
        .expect("prepare");
    let waiting = tokio::spawn({
        let server = server.clone();
        async move { server.reapply().await }
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    prepared.commit();
    let snapshot = waiting.await.expect("join").expect("reapply");
    assert_eq!(snapshot.config.listeners.len(), 2);
    assert_eq!(
        recorder.lines(),
        [
            "prepare web",
            "commit web",
            "prepare web",
            "commit web",
            "prepare api,web",
            "commit api,web",
            "prepare api,web",
            "commit api,web",
        ]
    );
}
