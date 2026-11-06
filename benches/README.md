# Benchmarks

How the performance of Wormway is measured, and the scripts that measure it against Nginx.

## Method

- **Open loop.** Send requests at a fixed rate, whatever the server does, and measure each
  latency from when the request was due. A closed-loop tool, where each connection sends its
  next request only after the last answer, slows down with the server and hides its stalls
  (coordinated omission).
- **Whole latency distributions.** Report p50, p99, p99.9 and the maximum rather than averages.
  Compare runs at the same rate, and look for the highest rate that still meets a latency target
  rather than for the highest throughput.
- **Warm up, then measure.** Discard a short warm-up, measure for 30 seconds, repeat every
  measurement three times and report the median.
- **Separate CPUs.** The load generator and the proxy should not share CPUs. `bench.py` pins the
  proxy to the upper half of the CPUs and the load generator and the upstream to the lower half,
  with `taskset`, and gives the proxy one thread or worker process per CPU it has.
- **Release builds.** `cargo build --release` uses fat LTO and one codegen unit.
- **Record the environment** with every result: hardware, operating system, kernel settings,
  versions and commit. `env.sh` prints them.

## Scripts

| Script | Purpose |
|---|---|
| `bench.py` | Builds Wormway once per allocator, runs the scenarios against Wormway and Nginx, and summarizes the results as Markdown tables. Linux only; the Python standard library only. |
| `env.sh` | Prints the environment of a run. |
| `load.sh URL RATE [DURATION] [CONNECTIONS]` | Warms up, then sends HTTP requests to `URL` at `RATE` per second with [oha](https://github.com/hatoo/oha), and saves the latency report and the environment in `results/`. For a quick look at one setup. |

`results/` is not committed.

## Scenarios

The upstream is a separate Nginx that answers `ok` on `/` and 1 MiB on `/1m`, kept alive by
both proxies. Both proxies leave their access logs off unless a scenario turns them on.

| # | Scenario | Load |
|---|---|---|
| 1 | Small responses, HTTP/1.1 keep-alive | rates from 2000 to 40000 per second, 64 connections |
| 2 | HTTP/2 over TLS | the same rates, 16 requests at once on each of 8 connections |
| 3 | A TLS handshake per request | rates from 200 to 5000 per second, no keep-alive |
| 4 | 1 MiB responses | rates from 50 to 800 per second, 16 connections |
| 5 | Memory of 10000 idle WebSocket connections | resident memory before and while they are held |
| 6 | One of two upstream targets stops for 15 seconds | 2000 per second for 40 seconds; Wormway with passive checks and `retry_on_reset`, Nginx with `max_fails`, which retries on the other target by default |
| 7 | Features turned on one by one: request headers, rate limit, API key, JSON and combined access logs, all | 5000 and 10000 per second |
| 8 | A configuration change every second, SIGHUP for both | 5000 per second for 40 seconds, against the same load without changes |

A rate ladder stops at the first rate where the proxy falls more than 10% behind, p99 passes
50 ms, or more than 1% of the requests fail.

Then Wormway alone, against its defaults: the system and mimalloc allocators on scenarios 1,
4 and 5; a backlog of 128 on scenario 3; the default pool of idle upstream connections against a
pool of one per thread, both with 256 connections; upstreams over h2c and over HTTP/2 with TLS on
scenario 1; and, with at least two CPUs for the proxy, one thread against several and
`reuseport`. `--scenarios` selects the variants too.

What each run records: oha's latency report, the CPU time and the resident memory of the proxy
(with its worker processes for Nginx), the connections that the kernel dropped from full accept
queues (`/proc/net/netstat`), and the requests per upstream connection (`stub_status` of the
upstream).

## On a Debian or Ubuntu server

Install the build tools, cmake included (Pingora builds zlib-ng with it), and Nginx from
nginx.org, for its current stable version, then stop the service it starts: `bench.py` starts its
own instances.

```sh
sudo apt install curl gnupg2 ca-certificates lsb-release build-essential cmake git
curl https://nginx.org/keys/nginx_signing.key | gpg --dearmor \
    | sudo tee /usr/share/keyrings/nginx-archive-keyring.gpg >/dev/null
echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/$(. /etc/os-release && echo "$ID") $(lsb_release -cs) nginx" \
    | sudo tee /etc/apt/sources.list.d/nginx.list
sudo apt update && sudo apt install nginx
sudo systemctl disable --now nginx
```

Install oha 1.9 or later, here the binary of its latest release for x86-64 (`oha-linux-arm64`
for ARM), and Rust:

```sh
sudo curl -L -o /usr/local/bin/oha https://github.com/hatoo/oha/releases/latest/download/oha-linux-amd64
sudo chmod +x /usr/local/bin/oha
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Build Wormway once per allocator, into `target/bench/`. The release profile links the whole
program at once, which needs more than 2 GB of memory: on smaller machines, add a swap file for
the build, and remove it before measuring, so that swapping does not distort the memory figures.

```sh
sudo fallocate -l 4G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile
python3 benches/bench.py build
sudo swapoff /swapfile && sudo rm /swapfile
```

Then a quick run, to check that everything works, and the full one. The full run takes several
hours, so start it in `tmux` or `screen`, or with `nohup`, to survive a lost SSH session.

```sh
python3 benches/bench.py run --quick
python3 benches/bench.py run
```

`--scenarios 1,3`, `--proxies wormway`, `--no-variants`, `--repeats`, `--duration` and
`--proxy-cpus` narrow a run down; `--help` lists them. `bench.py configs DIR` writes the
configurations that the proxies get, to read them.

Each run writes `benches/results/<time>/`: the configurations, the logs, a JSON file per
measurement and `summary.md`. To send a run, pack its directory:

```sh
tar czf <time>.tar.gz -C benches/results <time>
```

`bench.py soak --hours 24 --rate 5000` loads Wormway at a steady rate and records its memory
every minute, to compare the allocators over a long run.

## Caveats

- With the load generator and the upstream on the same machine as the proxy, the figures compare
  the proxies with each other; they do not predict a dedicated server. Where the tools' CPUs are
  saturated before the proxy's, the rate ladder stops early for both proxies alike.
- Scenario 3 measures what oha does: it may resume TLS sessions, which both proxies allow, so
  not every handshake is a full one. Wormway prefers the post-quantum key exchange
  `X25519MLKEM768`, which costs more than the `X25519` of OpenSSL before 3.5 (Debian 12, Ubuntu
  22.04 and 24.04), when the client offers it.
- Wormway keeps a pool of idle upstream connections per listener; Nginx one per worker process.
- Nginx allocates the connections of each worker up front, about 450 bytes each, so its resident
  memory grows with `worker_connections`: 4096, enough for every scenario but the fifth, which
  raises it to what its connections need.
- Nginx closes HTTP/2 connections after `keepalive_requests` too, and oha fails the requests in
  flight then, so the TLS server of Nginx has no such limit, as Wormway has none for HTTP/2.
