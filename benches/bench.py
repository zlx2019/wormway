#!/usr/bin/env python3
"""Benchmarks of Wormway against Nginx on one Linux machine, with the Python standard library.

    python3 benches/bench.py build                  # release binaries, one per allocator
    python3 benches/bench.py run [--quick] [...]    # the scenarios, see --help
    python3 benches/bench.py summarize DIR          # Markdown tables of a run
    python3 benches/bench.py configs DIR            # the configurations, to read them
    python3 benches/bench.py soak --hours N         # memory of a long run

README.md describes the method, the scenarios and what to install.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import resource
import shutil
import signal
import socket
import ssl
import statistics
import subprocess
import sys
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
# Binaries of `build`, one per allocator; target/ is not committed.
BINARIES = REPO / "target" / "bench"
ALLOCATORS = ("system", "jemalloc", "mimalloc")

# Ports on the loopback interface.
HTTP_PORT = 8080  # the proxy under test, plain HTTP
HTTPS_PORT = 8443  # the proxy under test, TLS with HTTP/2
ADMIN_PORT = 19872  # the Admin API of Wormway
UPSTREAM_PORT = 18080  # the upstream, HTTP/1.1
UPSTREAM_H2C_PORT = 18081  # the upstream, HTTP/2 without TLS
UPSTREAM_TLS_PORT = 18443  # the upstream, HTTP/2 over TLS
SECOND_UPSTREAM_PORT = 18082  # a second upstream, for scenario 6
STATUS_PORT = 18089  # stub_status of the upstream
WS_PORT = 18090  # the WebSocket upstream of scenario 5

# WebSocket connections that scenario 5 holds, 1000 with --quick. Each takes two through the proxy.
WS_CONNECTIONS = 10_000

# Latency above which a rate counts as too high, in seconds, and the share of errors.
P99_LIMIT = 0.050
ERROR_LIMIT = 0.01


# ---- Machine ----


@dataclass
class Layout:
    """Which CPUs the proxy under test gets, and which the load generator and the upstream share."""

    proxy: list[int]
    tools: list[int]

    @staticmethod
    def detect() -> Layout:
        """Splits the CPUs of this process in two: the upper half for the proxy."""
        cpus = sorted(os.sched_getaffinity(0))
        if len(cpus) < 2:
            sys.exit("at least 2 CPUs are needed: one for the proxy, one for the tools")
        half = len(cpus) // 2
        return Layout(proxy=cpus[half:], tools=cpus[:half])

    def pin(self, cpus: list[int], command: list[str]) -> list[str]:
        """Prefixes `command` with taskset, to run it on `cpus` only."""
        return ["taskset", "-c", ",".join(map(str, cpus)), *command]


def check_tools() -> None:
    """Exits with a message off Linux, or when a program the benchmarks need is missing."""
    if sys.platform != "linux":
        sys.exit("the benchmarks run on Linux: they read /proc and pin processes with taskset")
    missing = [tool for tool in ("nginx", "oha", "taskset", "openssl") if shutil.which(tool) is None]
    if missing:
        sys.exit(f"missing programs: {', '.join(missing)}; see benches/README.md")


def raise_open_files() -> int:
    """Raises the limit of open files as far as allowed, and returns it; the processes started
    inherit it."""
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    wanted = 200_000 if hard == resource.RLIM_INFINITY else min(200_000, hard)
    if soft < wanted:
        resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))
    soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    # To standard error: the WebSocket clients of scenario 5 answer on standard output.
    if soft < 2 * WS_CONNECTIONS + 1024:
        print(f"warning: only {soft} open files allowed, scenario 5 needs about {2 * WS_CONNECTIONS + 1024}",
              file=sys.stderr, flush=True)
    return soft


def clean_env() -> dict[str, str]:
    """The environment of the processes started, without proxy settings, which would send the
    load through another proxy."""
    return {key: value for key, value in os.environ.items() if not key.lower().endswith("_proxy")}


def nginx_version() -> tuple[int, int, int]:
    """The version of nginx, such as (1, 28, 0)."""
    output = subprocess.run(["nginx", "-v"], capture_output=True, text=True).stderr
    found = re.search(r"nginx/(\d+)\.(\d+)\.(\d+)", output)
    if not found:
        sys.exit(f"cannot tell the version of nginx from: {output.strip()}")
    return tuple(int(part) for part in found.groups())  # type: ignore[return-value]


# Requests of the benchmarks themselves, which must not go through a proxy of the environment.
DIRECT = urllib.request.build_opener(urllib.request.ProxyHandler({}))


# ---- Processes ----


class Process:
    """A process started for the benchmarks, stopped when the benchmarks end."""

    running: list[Process] = []

    def __init__(self, name: str, command: list[str], log: Path, cwd: Path | None = None) -> None:
        """Starts `command` with its output in `log`."""
        self.name = name
        self.log = log
        with open(log, "ab") as output:
            self.popen = subprocess.Popen(
                command,
                stdout=output,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                cwd=cwd,
                env=clean_env(),
                start_new_session=True,
            )
        Process.running.append(self)

    @property
    def pid(self) -> int:
        """The process ID."""
        return self.popen.pid

    def send_signal(self, signum: int) -> None:
        """Sends `signum` to the process."""
        if self.popen.poll() is None:
            os.kill(self.pid, signum)

    def stop(self, signum: int = signal.SIGTERM, timeout: float = 10) -> None:
        """Stops the process and its children, killing them after `timeout` seconds."""
        if self.popen.poll() is None:
            try:
                os.killpg(self.pid, signum)
                self.popen.wait(timeout)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(self.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                self.popen.wait()
        if self in Process.running:
            Process.running.remove(self)

    @classmethod
    def stop_all(cls) -> None:
        """Stops every process still running."""
        for process in list(cls.running):
            process.stop(timeout=5)


def wait_for_port(port: int, process: Process, timeout: float = 20) -> None:
    """Waits until something accepts connections on loopback `port`, or exits if `process` ended."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process.popen.poll() is not None:
            sys.exit(f"{process.name} exited, see {process.log}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return
        except OSError:
            time.sleep(0.1)
    sys.exit(f"{process.name} does not listen on port {port}, see {process.log}")


def process_tree(pid: int) -> list[int]:
    """`pid` and its descendants, from /proc."""
    children: dict[int, list[int]] = {}
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = (entry / "stat").read_text()
        except OSError:
            continue
        # The command name is in parentheses and may hold spaces, so split after it.
        parent = int(stat[stat.rindex(")") + 2 :].split()[1])
        children.setdefault(parent, []).append(int(entry.name))
    tree, queue = [], [pid]
    while queue:
        current = queue.pop()
        tree.append(current)
        queue.extend(children.get(current, []))
    return tree


@dataclass
class Usage:
    """CPU time and memory of a process tree at one moment."""

    cpu_seconds: float
    rss_bytes: int
    peak_rss_bytes: int

    @staticmethod
    def of(pid: int) -> Usage:
        """Adds up the user and system time and the resident memory of `pid` and its children. The
        time includes children that ended, such as the workers that Nginx replaces on a reload."""
        ticks = os.sysconf("SC_CLK_TCK")
        cpu, rss, peak = 0.0, 0, 0
        for member in process_tree(pid):
            try:
                stat = Path(f"/proc/{member}/stat").read_text()
                status = Path(f"/proc/{member}/status").read_text()
            except OSError:
                continue
            fields = stat[stat.rindex(")") + 2 :].split()
            # utime and stime, then cutime and cstime of the children it waited for.
            cpu += sum(int(value) for value in fields[11:15]) / ticks
            rss += kib(status, "VmRSS") * 1024
            peak += kib(status, "VmHWM") * 1024
        return Usage(cpu, rss, peak)


def kib(status: str, key: str) -> int:
    """A value in KiB from /proc/<pid>/status."""
    found = re.search(rf"^{key}:\s+(\d+) kB", status, re.MULTILINE)
    return int(found.group(1)) if found else 0


def listen_counters() -> dict[str, int]:
    """Counters of the kernel about full accept queues, from /proc/net/netstat."""
    lines = Path("/proc/net/netstat").read_text().splitlines()
    wanted = ("ListenOverflows", "ListenDrops", "TCPReqQFullDrop", "TCPReqQFullDoCookies")
    counters: dict[str, int] = {}
    for names, values in zip(lines[::2], lines[1::2]):
        if names.startswith("TcpExt:"):
            for name, value in zip(names.split()[1:], values.split()[1:]):
                if name in wanted:
                    counters[name] = int(value)
    return counters


def upstream_status() -> dict[str, int] | None:
    """Connections accepted and requests served by the upstream, from its stub_status."""
    try:
        with DIRECT.open(f"http://127.0.0.1:{STATUS_PORT}/status", timeout=2) as answer:
            text = answer.read().decode()
    except OSError:
        return None
    numbers = text.splitlines()[2].split()
    return {"accepts": int(numbers[0]), "requests": int(numbers[2])}


# ---- Files of a run ----


@dataclass
class Work:
    """The directory of a run: configurations, certificate, files served, logs and results."""

    root: Path
    nginx: tuple[int, int, int] = (1, 28, 0)
    open_files: int = 65_536

    def prepare(self) -> None:
        """Creates the directory, an ECDSA P-256 certificate for 127.0.0.1 signed by a CA of its
        own, and the 1 MiB file."""
        (self.root / "data").mkdir(parents=True, exist_ok=True)
        if not self.path("cert.pem").exists():
            curve = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"]
            openssl = lambda *args: subprocess.run(["openssl", *args], check=True, capture_output=True)
            openssl("req", "-x509", *curve, "-keyout", str(self.path("ca.key")), "-out", str(self.path("ca.pem")),
                    "-days", "30", "-subj", "/CN=Wormway bench CA")
            openssl("req", *curve, "-keyout", str(self.path("key.pem")), "-out", str(self.path("cert.csr")),
                    "-subj", "/CN=bench.local")
            self.path("cert.ext").write_text("subjectAltName=DNS:bench.local,IP:127.0.0.1\n"
                                             "basicConstraints=CA:FALSE\n")
            openssl("x509", "-req", "-in", str(self.path("cert.csr")), "-CA", str(self.path("ca.pem")),
                    "-CAkey", str(self.path("ca.key")), "-CAcreateserial", "-days", "30",
                    "-extfile", str(self.path("cert.ext")), "-out", str(self.path("cert.pem")))
        large = self.root / "1m.bin"
        if not large.exists():
            large.write_bytes(os.urandom(1 << 20))

    def path(self, name: str) -> Path:
        """A file of the run."""
        return self.root / name


@dataclass
class Settings:
    """What a proxy is configured with for one scenario: the defaults unless a scenario or a variant
    changes them."""

    threads: int = 1
    backlog: int = 4096
    reuseport: bool = False
    pool_size: int = 128
    upstream_protocol: str = "h1"  # h1, h2c or h2
    features: tuple[str, ...] = ()  # headers, ratelimit, apikey, accesslog-json, accesslog-combined
    targets: tuple[int, ...] = ()  # ports of the upstream targets; the upstream of the protocol if empty
    generation: int = 0  # changes a response header, for the reloads of scenario 8
    # Of each Nginx worker, which allocates them up front, about 450 bytes each: enough for every
    # scenario but the fifth, which raises it.
    worker_connections: int = 4096


API_KEY = "bench-key-0123456789abcdef"


def wormway_config(work: Work, settings: Settings) -> str:
    """The configuration of Wormway, in file mode."""
    upstream_port = {"h1": UPSTREAM_PORT, "h2c": UPSTREAM_H2C_PORT, "h2": UPSTREAM_TLS_PORT}[
        settings.upstream_protocol
    ]
    targets = settings.targets or (upstream_port,)
    lines = [
        "version = 1",
        "[server]",
        f"threads = {settings.threads}",
        f"backlog = {settings.backlog}",
        f"reuseport = {str(settings.reuseport).lower()}",
        f"upstream_keepalive_pool_size = {settings.pool_size}",
        'shutdown_timeout = "1s"',
        "[log]",
        'level = "warn"',
    ]
    for kind in ("json", "combined"):
        if f"accesslog-{kind}" in settings.features:
            lines += ["[log.access]", f'format = "{kind}"', f'path = "{work.path("access.log")}"']
    lines += [
        "[admin]",
        f'listen = "127.0.0.1:{ADMIN_PORT}"',
        "[storage]",
        f'data_dir = "{work.path("data")}"',
        "[config]",
        'source = "file"',
        "[listeners.web]",
        f'listen = ["127.0.0.1:{HTTP_PORT}"]',
        'protocol = "http"',
        "[listeners.websecure]",
        f'listen = ["127.0.0.1:{HTTPS_PORT}"]',
        'protocol = "http"',
        'tls = { certificates = ["bench"] }',
        "[certificates.bench]",
        f'cert = "{work.path("cert.pem")}"',
        f'key = "{work.path("key.pem")}"',
        "[routes.app]",
        'upstream = "app"',
        f'response_headers = {{ set = {{ "X-Bench-Generation" = "{settings.generation}" }} }}',
    ]
    if "headers" in settings.features:
        lines.append(
            'request_headers = { set = { "X-Bench-A" = "1", "X-Bench-B" = "2" }, remove = ["X-Bench-C"] }'
        )
    if "ratelimit" in settings.features:
        lines.append('rate_limit = { requests = 1000000, per = "1s", key = "client_ip" }')
    if "apikey" in settings.features:
        lines.append("auth = { api_key = true }")
    lines += [
        "[routes.ws]",
        'match = { paths = ["/ws"] }',
        'upstream = "ws"',
        'timeouts = { read = "1h" }',
        "[upstreams.app]",
        "targets = [" + ", ".join(f'"127.0.0.1:{port}"' for port in targets) + "]",
    ]
    if settings.upstream_protocol != "h1":
        lines.append(f'protocol = "{settings.upstream_protocol}"')
    if settings.upstream_protocol == "h2":
        lines.append(f'tls = {{ ca = "{work.path("ca.pem")}" }}')
    if len(targets) > 1:
        lines.append("passive = { max_fails = 1, fail_timeout = \"10s\" }")
    lines += ["[upstreams.ws]", f'targets = ["127.0.0.1:{WS_PORT}"]']
    if "apikey" in settings.features:
        digest = hashlib.sha256(API_KEY.encode()).hexdigest()
        lines += ["[consumers.bench]", f'api_keys = ["sha256:{digest}"]']
    return "\n".join(lines) + "\n"


def nginx_common(work: Work, name: str, workers: int, connections: int = Settings.worker_connections) -> list[str]:
    """The top of an nginx configuration: workers, files of the run and limits."""
    lines = [
        f"worker_processes {workers};",
        f"worker_rlimit_nofile {work.open_files};",
        f"pid {work.path(name + '.pid')};",
        f"error_log {work.path(name + '-error.log')} warn;",
        f"events {{ worker_connections {min(connections, work.open_files)}; }}",
    ]
    if os.geteuid() == 0:
        # Workers would run as nobody, which cannot read the files of the run.
        lines.insert(0, "user root;")
    return lines


def nginx_http2(work: Work) -> str:
    """How this nginx turns HTTP/2 on in a server: `http2 on;` since 1.25.1."""
    return "http2 on;" if work.nginx >= (1, 25, 1) else ""


def nginx_listen(work: Work, port: int, extra: str = "", backlog: int = 4096) -> str:
    """A listen directive; before 1.25.1 HTTP/2 is a parameter of it."""
    http2 = " http2" if "http2" in extra and work.nginx < (1, 25, 1) else ""
    ssl = " ssl" if "ssl" in extra else ""
    return f"listen 127.0.0.1:{port}{ssl}{http2} backlog={backlog};"


def nginx_proxy_config(work: Work, settings: Settings) -> str:
    """The configuration of Nginx as the proxy under test, the counterpart of `wormway_config`."""
    lines = nginx_common(work, "nginx", settings.threads, settings.worker_connections)
    targets = "\n".join(
        f"        server 127.0.0.1:{port} max_fails=1 fail_timeout=10s;"
        for port in settings.targets or (UPSTREAM_PORT,)
    )
    access_log = "access_log off;"
    for kind, format_name in (("json", "bench_json"), ("combined", "combined")):
        if f"accesslog-{kind}" in settings.features:
            access_log = f"access_log {work.path('access.log')} {format_name};"
    route_extra = []
    if "headers" in settings.features:
        route_extra += ['proxy_set_header X-Bench-A "1";', 'proxy_set_header X-Bench-B "2";',
                        'proxy_set_header X-Bench-C "";']
    if "ratelimit" in settings.features:
        route_extra.append("limit_req zone=bench burst=1000000 nodelay;")
    if "apikey" in settings.features:
        route_extra.append(f'if ($http_x_api_key != "{API_KEY}") {{ return 401; }}')
    locations = [
        "        location / {",
        "            proxy_pass http://app;",
        "            proxy_http_version 1.1;",
        '            proxy_set_header Connection "";',
        "            proxy_next_upstream error timeout;",
        "            proxy_next_upstream_tries 2;",
        f'            add_header X-Bench-Generation "{settings.generation}";',
        *(f"            {line}" for line in route_extra),
        "        }",
        "        location /ws {",
        "            proxy_pass http://ws;",
        "            proxy_http_version 1.1;",
        "            proxy_set_header Upgrade $http_upgrade;",
        '            proxy_set_header Connection "upgrade";',
        "            proxy_read_timeout 1h;",
        "        }",
    ]
    # Wormway limits the requests of HTTP/1.1 connections only. Nginx closes HTTP/2 connections
    # after keepalive_requests too, since 1.19.7, and oha fails the requests in flight then: lift it
    # on the TLS server, whose only HTTP/1.1 load, scenario 3, does not keep connections alive.
    h2_requests = "keepalive_requests" if work.nginx >= (1, 19, 7) else "http2_max_requests"
    lines += [
        "http {",
        "    log_format bench_json escape=json '{\"time\":\"$time_iso8601\",\"client_ip\":\"$remote_addr\","
        "\"method\":\"$request_method\",\"uri\":\"$request_uri\",\"status\":$status,"
        "\"duration\":$request_time,\"upstream_duration\":\"$upstream_response_time\"}';",
        f"    {access_log}",
        "    keepalive_timeout 75s;",
        "    keepalive_requests 1000;",
        "    limit_req_zone $binary_remote_addr zone=bench:10m rate=1000000r/s;",
        "    upstream app {",
        targets,
        f"        keepalive {settings.pool_size};",
        "    }",
        f"    upstream ws {{ server 127.0.0.1:{WS_PORT}; }}",
        "    server {",
        f"        {nginx_listen(work, HTTP_PORT, backlog=settings.backlog)}",
        *locations,
        "    }",
        "    server {",
        f"        {nginx_listen(work, HTTPS_PORT, 'ssl http2', backlog=settings.backlog)}",
        f"        {nginx_http2(work)}",
        f"        {h2_requests} 1000000000;",
        f"        ssl_certificate {work.path('cert.pem')};",
        f"        ssl_certificate_key {work.path('key.pem')};",
        *locations,
        "    }",
        "}",
    ]
    return "\n".join(lines) + "\n"


def upstream_config(work: Work, name: str, port: int, with_extras: bool) -> str:
    """The configuration of an upstream nginx: a small answer on /, 1 MiB on /1m, and with
    `with_extras` HTTP/2 without TLS, HTTP/2 over TLS and its stub_status."""
    lines = nginx_common(work, name, 1)
    lines += [
        "http {",
        "    access_log off;",
        "    sendfile on;",
        "    keepalive_timeout 300s;",
        "    keepalive_requests 1000000;",
        "    default_type text/plain;",
        "    server {",
        f"        {nginx_listen(work, port)}",
        '        location / { return 200 "ok\\n"; }',
        f"        location = /1m {{ alias {work.path('1m.bin')}; }}",
        "    }",
    ]
    if with_extras:
        lines += [
            "    server {",
            f"        {nginx_listen(work, UPSTREAM_H2C_PORT, 'http2')}",
            f"        {nginx_http2(work)}",
            '        location / { return 200 "ok\\n"; }',
            "    }",
            "    server {",
            f"        {nginx_listen(work, UPSTREAM_TLS_PORT, 'ssl http2')}",
            f"        {nginx_http2(work)}",
            f"        ssl_certificate {work.path('cert.pem')};",
            f"        ssl_certificate_key {work.path('key.pem')};",
            '        location / { return 200 "ok\\n"; }',
            "    }",
            "    server {",
            f"        {nginx_listen(work, STATUS_PORT)}",
            "        location = /status { stub_status; }",
            "    }",
        ]
    lines.append("}")
    return "\n".join(lines) + "\n"


# ---- Proxies under test ----


class Proxy:
    """The proxy under test, started with the settings of a scenario."""

    def __init__(self, kind: str, binary: Path | None, work: Work, layout: Layout) -> None:
        """A proxy of `kind`, wormway or nginx; `binary` is the Wormway to run."""
        self.kind = kind
        self.binary = binary
        self.work = work
        self.layout = layout
        self.process: Process | None = None
        self.settings = Settings()

    def config_text(self, settings: Settings) -> str:
        """The configuration for `settings`."""
        if self.kind == "wormway":
            return wormway_config(self.work, settings)
        return nginx_proxy_config(self.work, settings)

    def config_path(self) -> Path:
        """Where the configuration is written."""
        return self.work.path("wormway.toml" if self.kind == "wormway" else "nginx.conf")

    def start(self, settings: Settings) -> None:
        """Writes the configuration and starts the proxy on its CPUs."""
        self.stop()
        self.settings = settings
        self.config_path().write_text(self.config_text(settings))
        if self.kind == "wormway":
            command = [str(self.binary), "run", "-c", str(self.config_path())]
        else:
            command = ["nginx", "-p", str(self.work.root), "-c", str(self.config_path()),
                       "-e", str(self.work.path("nginx-error.log")), "-g", "daemon off;"]
        log = self.work.path(f"{self.kind}.log")
        self.process = Process(self.kind, self.layout.pin(self.layout.proxy, command), log)
        wait_for_port(HTTP_PORT, self.process)
        wait_for_port(HTTPS_PORT, self.process)
        self.smoke(log)

    def smoke(self, log: Path) -> None:
        """Exits unless the proxy answers 200 over HTTP and HTTPS, so that a broken configuration
        does not spend hours measuring errors."""
        unverified = ssl.create_default_context()
        unverified.check_hostname = False
        unverified.verify_mode = ssl.CERT_NONE
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                             urllib.request.HTTPSHandler(context=unverified))
        for url in (f"{HTTP}/", f"{HTTPS}/"):
            request = urllib.request.Request(url, headers={"X-API-Key": API_KEY})
            try:
                with opener.open(request, timeout=5) as answer:
                    body = answer.read()
            except OSError as error:
                sys.exit(f"{self.kind} does not answer {url}: {error}; see {log}")
            if body != b"ok\n":
                sys.exit(f"{self.kind} answers {url} with {body[:80]!r}; see {log}")

    def reload(self, settings: Settings) -> None:
        """Rewrites the configuration and makes the proxy read it again: SIGHUP for both."""
        self.settings = settings
        self.config_path().write_text(self.config_text(settings))
        if self.process:
            self.process.send_signal(signal.SIGHUP)

    def stop(self) -> None:
        """Stops the proxy, if running."""
        if self.process:
            # Nginx stops at once on SIGTERM; Wormway closes its connections within a second.
            self.process.stop()
            self.process = None

    @property
    def pid(self) -> int:
        """The process ID of the proxy."""
        assert self.process is not None
        return self.process.pid


def start_upstreams(work: Work, layout: Layout, second: bool = False) -> list[Process]:
    """Starts the upstream nginx, and with `second` another one on its own port, on the tool CPUs."""
    started = []
    for name, port, extras in (("upstream", UPSTREAM_PORT, True), ("upstream2", SECOND_UPSTREAM_PORT, False)):
        if name == "upstream2" and not second:
            continue
        config = work.path(f"{name}.conf")
        config.write_text(upstream_config(work, name, port, extras))
        command = ["nginx", "-p", str(work.root), "-c", str(config), "-e", str(work.path(name + "-error.log")),
                   "-g", "daemon off;"]
        process = Process(name, layout.pin(layout.tools, command), work.path(name + ".log"))
        wait_for_port(port, process)
        started.append(process)
    return started


# ---- Load ----


@dataclass
class Load:
    """How oha loads the proxy: the URL and the flags besides rate and duration."""

    url: str
    connections: int = 64
    flags: tuple[str, ...] = ()


def run_oha(layout: Layout, load: Load, rate: float, duration: float, output: Path | None,
            errors: Path | None = None) -> subprocess.Popen:
    """Starts oha at `rate` requests per second for `duration` whole seconds, writing JSON to
    `output` and its messages to `errors`."""
    command = ["oha", "--no-tui", "-q", f"{rate:g}", "-z", f"{max(1, round(duration))}s",
               "-c", str(load.connections), *load.flags]
    if output:
        command += ["--latency-correction", "--output-format", "json", "-o", str(output)]
    command.append(load.url)
    stderr = open(errors, "wb") if errors else subprocess.DEVNULL
    try:
        return subprocess.Popen(layout.pin(layout.tools, command), stdout=subprocess.DEVNULL,
                                stderr=stderr, env=clean_env())
    finally:
        if errors:
            stderr.close()


@dataclass
class Options:
    """How long and how often each measurement runs."""

    warmup: float
    duration: float
    repeats: int
    quick: bool


def measure(proxy: Proxy, layout: Layout, load: Load, rate: float, options: Options, record: Path,
            during=None) -> dict:
    """Warms up, then loads the proxy at `rate` and records the latencies, the CPU time and memory
    of the proxy, the full accept queues of the kernel and the reuse of upstream connections.
    `during` is called once a second while measuring, with the seconds elapsed."""
    if options.warmup > 0:
        warm = run_oha(layout, load, rate, options.warmup, None)
        warm.wait()
    report, messages = record.with_suffix(".oha.json"), record.with_suffix(".oha.log")
    before, queues, upstream = Usage.of(proxy.pid), listen_counters(), upstream_status()
    started = time.monotonic()
    oha = run_oha(layout, load, rate, options.duration, report, messages)
    second = 0
    while oha.poll() is None:
        time.sleep(0.05)
        elapsed = time.monotonic() - started
        if during and elapsed >= second + 1:
            second += 1
            during(second)
    wall = time.monotonic() - started
    after, queues_after, upstream_after = Usage.of(proxy.pid), listen_counters(), upstream_status()
    result = {
        "proxy": proxy.kind,
        "rate": rate,
        "wall_seconds": wall,
        "cpu_seconds": after.cpu_seconds - before.cpu_seconds,
        "rss_bytes": after.rss_bytes,
        "peak_rss_bytes": after.peak_rss_bytes,
        "listen_queue": {name: queues_after[name] - queues.get(name, 0) for name in queues_after},
        "oha_stderr": messages.read_text(errors="replace")[-2000:] if messages.exists() else "",
    }
    if upstream and upstream_after:
        result["upstream_connections"] = upstream_after["accepts"] - upstream["accepts"]
        result["upstream_requests"] = upstream_after["requests"] - upstream["requests"]
    try:
        result["oha"] = json.loads(report.read_text())
    except (OSError, json.JSONDecodeError):
        result["oha"] = None
    record.write_text(json.dumps(result, indent=1))
    return result


def outcome(result: dict) -> tuple[float, float, float]:
    """Requests per second, p99 latency and share of errors of a measurement. Requests that were
    still waiting when the run ended count for neither: oha's own rate counts them."""
    report = result.get("oha") or {}
    summary = report.get("summary", {})
    statuses = report.get("statusCodeDistribution", {})
    errors = report.get("errorDistribution", {})
    ok = sum(count for status, count in statuses.items() if status.startswith("2"))
    failed = sum(count for status, count in statuses.items() if not status.startswith("2"))
    failed += sum(count for reason, count in errors.items() if "deadline" not in reason)
    total = ok + failed
    seconds = summary.get("total") or 0.0
    p99 = report.get("latencyPercentiles", {}).get("p99") or 0.0
    return (total / seconds if seconds else 0.0), p99, (failed / total if total else 1.0)


def ladder(proxy: Proxy, layout: Layout, load: Load, rates: list[float], options: Options, out: Path) -> None:
    """Measures at each rate, `options.repeats` times, and stops at the first rate where the proxy
    falls behind, answers too slowly or fails too often."""
    out.mkdir(parents=True, exist_ok=True)
    for rate in rates:
        results = []
        for repeat in range(1, options.repeats + 1):
            print(f"    {rate:>8.0f}/s, run {repeat}/{options.repeats}", flush=True)
            results.append(measure(proxy, layout, load, rate, options, out / f"{int(rate)}-{repeat}.json"))
        achieved, p99, errors = (statistics.median(values) for values in zip(*map(outcome, results)))
        if achieved < 0.9 * rate or p99 > P99_LIMIT or errors > ERROR_LIMIT:
            print(f"    stops at {rate:.0f}/s: {achieved:.0f}/s, p99 {p99 * 1000:.1f} ms, "
                  f"{errors:.1%} errors", flush=True)
            break


# ---- Scenarios ----


def rates(full: list[float], quick: list[float], options: Options) -> list[float]:
    """The rates of a scenario."""
    return quick if options.quick else full


HTTP = f"http://127.0.0.1:{HTTP_PORT}"
HTTPS = f"https://127.0.0.1:{HTTPS_PORT}"


def scenario_1(proxy: Proxy, run: Run) -> None:
    """Small responses over HTTP/1.1 kept-alive connections."""
    proxy.start(run.settings())
    ladder(proxy, run.layout, Load(f"{HTTP}/"), rates([2000, 5000, 10000, 15000, 20000, 30000, 40000],
                                                       [2000, 10000], run.options), run.options, run.out(1, proxy))


def scenario_2(proxy: Proxy, run: Run) -> None:
    """HTTP/2 over TLS, 16 requests at once on each of 8 connections."""
    proxy.start(run.settings())
    load = Load(f"{HTTPS}/", connections=8, flags=("--http2", "-p", "16", "--insecure"))
    ladder(proxy, run.layout, load, rates([2000, 5000, 10000, 15000, 20000, 30000, 40000], [2000, 10000],
                                          run.options), run.options, run.out(2, proxy))


def scenario_3(proxy: Proxy, run: Run) -> None:
    """A TLS handshake for every request: no keep-alive."""
    proxy.start(run.settings())
    load = Load(f"{HTTPS}/", flags=("--disable-keepalive", "--insecure"))
    ladder(proxy, run.layout, load, rates([200, 500, 1000, 2000, 3000, 5000], [200, 1000], run.options),
           run.options, run.out(3, proxy))


def scenario_4(proxy: Proxy, run: Run) -> None:
    """Responses of 1 MiB."""
    proxy.start(run.settings())
    load = Load(f"{HTTP}/1m", connections=16)
    ladder(proxy, run.layout, load, rates([50, 100, 200, 400, 800], [50, 200], run.options), run.options,
           run.out(4, proxy))


def scenario_5(proxy: Proxy, run: Run) -> None:
    """Memory of idle WebSocket connections: the growth of the resident memory of the proxy."""
    count = 1000 if run.options.quick else WS_CONNECTIONS
    settings = run.settings()
    settings.worker_connections = max(settings.worker_connections, 2 * count + 1024)
    out = run.out(5, proxy)
    out.mkdir(parents=True, exist_ok=True)
    upstream = Process("ws-upstream", run.layout.pin(run.layout.tools, [sys.executable, __file__, "ws-upstream",
                                                                         str(WS_PORT)]),
                       run.work.path("ws-upstream.log"))
    wait_for_port(WS_PORT, upstream)
    try:
        for repeat in range(1, run.options.repeats + 1):
            print(f"    {count} connections, run {repeat}/{run.options.repeats}", flush=True)
            proxy.start(settings)
            time.sleep(2)
            base = Usage.of(proxy.pid)
            clients = subprocess.Popen(
                run.layout.pin(run.layout.tools, [sys.executable, __file__, "ws-clients", str(HTTP_PORT),
                                                  str(count)]),
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=clean_env())
            ready = clients.stdout.readline().decode().strip() if clients.stdout else ""
            time.sleep(5)
            held = Usage.of(proxy.pid)
            if clients.stdin:
                clients.stdin.close()
            clients.wait(30)
            opened = int(ready.split()[1]) if ready.startswith("ready") else 0
            result = {
                "proxy": proxy.kind,
                "connections": opened,
                "wanted": count,
                "base_rss_bytes": base.rss_bytes,
                "held_rss_bytes": held.rss_bytes,
                "per_connection_bytes": (held.rss_bytes - base.rss_bytes) / opened if opened else None,
                "clients_stderr": clients.stderr.read().decode(errors="replace")[-2000:] if clients.stderr else "",
            }
            (out / f"{count}-{repeat}.json").write_text(json.dumps(result, indent=1))
    finally:
        upstream.stop()


def scenario_6(proxy: Proxy, run: Run) -> None:
    """One of two upstream targets stops after 10 seconds and comes back 15 seconds later."""
    rate = 1000 if run.options.quick else 2000
    duration = 40.0
    second_upstream = start_upstreams_second(run)
    out = run.out(6, proxy)
    out.mkdir(parents=True, exist_ok=True)
    settings = run.settings()
    settings.targets = (UPSTREAM_PORT, SECOND_UPSTREAM_PORT)
    try:
        for repeat in range(1, run.options.repeats + 1):
            print(f"    {rate}/s with a failing target, run {repeat}/{run.options.repeats}", flush=True)
            proxy.start(settings)
            state = {"second": second_upstream}

            def during(elapsed: int) -> None:
                """Stops the second target at 10 seconds and starts it again at 25."""
                if elapsed == 10:
                    state["second"].stop()
                elif elapsed == 25:
                    state["second"] = start_upstreams_second(run)

            options = Options(warmup=run.options.warmup, duration=duration, repeats=1, quick=run.options.quick)
            measure(proxy, run.layout, Load(f"{HTTP}/"), rate, options, out / f"{rate}-{repeat}.json", during)
            second_upstream = state["second"]
    finally:
        second_upstream.stop()


def start_upstreams_second(run: Run) -> Process:
    """Starts the second upstream of scenario 6."""
    config = run.work.path("upstream2.conf")
    config.write_text(upstream_config(run.work, "upstream2", SECOND_UPSTREAM_PORT, False))
    command = ["nginx", "-p", str(run.work.root), "-c", str(config), "-e",
               str(run.work.path("upstream2-error.log")), "-g", "daemon off;"]
    process = Process("upstream2", run.layout.pin(run.layout.tools, command), run.work.path("upstream2.log"))
    wait_for_port(SECOND_UPSTREAM_PORT, process)
    return process


FEATURES = ("base", "headers", "ratelimit", "apikey", "accesslog-json", "accesslog-combined", "all")


def scenario_7(proxy: Proxy, run: Run) -> None:
    """The cost of features, turned on one by one at fixed rates."""
    for feature in FEATURES:
        print(f"   feature {feature}", flush=True)
        settings = run.settings()
        if feature == "all":
            settings.features = ("headers", "ratelimit", "apikey", "accesslog-json")
        elif feature != "base":
            settings.features = (feature,)
        proxy.start(settings)
        flags = ("-H", f"X-API-Key: {API_KEY}") if "apikey" in settings.features else ()
        out = run.out(7, proxy) / feature
        out.mkdir(parents=True, exist_ok=True)
        for rate in rates([5000, 10000], [5000], run.options):
            for repeat in range(1, run.options.repeats + 1):
                print(f"    {rate}/s, run {repeat}/{run.options.repeats}", flush=True)
                measure(proxy, run.layout, Load(f"{HTTP}/", flags=flags), rate, run.options,
                        out / f"{rate}-{repeat}.json")
        access_log = run.work.path("access.log")
        if access_log.exists():
            access_log.unlink()


def scenario_8(proxy: Proxy, run: Run) -> None:
    """Configuration changes once a second while loaded, against the same load without them."""
    rate = 2000 if run.options.quick else 5000
    for mode in ("steady", "reload"):
        out = run.out(8, proxy) / mode
        out.mkdir(parents=True, exist_ok=True)
        for repeat in range(1, run.options.repeats + 1):
            print(f"    {mode}, {rate}/s, run {repeat}/{run.options.repeats}", flush=True)
            settings = run.settings()
            proxy.start(settings)
            reloads = []

            def during(elapsed: int) -> None:
                """Changes a response header every second after the first five."""
                if mode == "reload" and 5 <= elapsed < 35:
                    settings.generation += 1
                    proxy.reload(settings)
                    reloads.append(elapsed)

            options = Options(warmup=run.options.warmup, duration=40.0, repeats=1, quick=run.options.quick)
            record = out / f"{rate}-{repeat}.json"
            result = measure(proxy, run.layout, Load(f"{HTTP}/"), rate, options, record, during)
            result["reloads"] = len(reloads)
            record.write_text(json.dumps(result, indent=1))


SCENARIOS = {1: scenario_1, 2: scenario_2, 3: scenario_3, 4: scenario_4, 5: scenario_5, 6: scenario_6,
             7: scenario_7, 8: scenario_8}


# ---- Variants of Wormway alone ----


def variants(run: Run, wormway: Proxy, scenarios: list[int]) -> None:
    """Wormway with other settings or allocators, against its defaults, on those of `scenarios`
    that each needs: allocators on scenarios 1, 4 and 5; backlog 128 on scenario 3; the default
    pool of idle upstream connections against a pool of one per thread, both with 256
    connections; upstreams over HTTP/2; and with 4 CPUs or more, threads and reuseport."""
    allocators = [name for name in ALLOCATORS[1:] if (BINARIES / f"wormway-{name}").exists()]
    for name in allocators:
        numbers = [number for number in (1, 4, 5) if number in scenarios]
        if not numbers:
            break
        print(f"  allocator {name}", flush=True)
        proxy = Proxy("wormway", BINARIES / f"wormway-{name}", run.work, run.layout)
        for number in numbers:
            run.variant = f"alloc-{name}"
            SCENARIOS[number](proxy, run)
        proxy.stop()
    if not allocators:
        print("  no binaries of other allocators: run `bench.py build` first", flush=True)
    if 3 in scenarios:
        run.variant = "backlog-128"
        print("  backlog 128", flush=True)
        run.overrides = {"backlog": 128}
        scenario_3(wormway, run)
    if 1 in scenarios:
        for size in (Settings.pool_size, 1):
            run.variant, run.overrides = f"pool-{size}", {"pool_size": size}
            print(f"  pool of {size} per thread, 256 connections", flush=True)
            wormway.start(run.settings())
            ladder(wormway, run.layout, Load(f"{HTTP}/", connections=256),
                   rates([2000, 5000, 10000, 20000], [5000], run.options), run.options, run.out(1, wormway))
        for protocol in ("h2c", "h2"):
            run.variant, run.overrides = f"upstream-{protocol}", {"upstream_protocol": protocol}
            print(f"  upstreams over {protocol}", flush=True)
            scenario_1(wormway, run)
    numbers = [number for number in (1, 3) if number in scenarios]
    if numbers and len(run.layout.proxy) < 2:
        print("  threads and reuseport need 2 CPUs for the proxy, 4 in all: skipped", flush=True)
    elif numbers:
        if 1 in numbers:
            run.variant, run.overrides = "threads-1", {"threads": 1}
            print("  one thread", flush=True)
            scenario_1(wormway, run)
        run.variant, run.overrides = "reuseport", {"reuseport": True}
        print("  reuseport", flush=True)
        for number in numbers:
            SCENARIOS[number](wormway, run)
    run.variant, run.overrides = "", {}
    wormway.stop()


# ---- Runs ----


@dataclass
class Run:
    """One run of the benchmarks: where it writes, how the machine is split and how long it takes."""

    work: Work
    layout: Layout
    options: Options
    variant: str = ""
    overrides: dict = field(default_factory=dict)

    def settings(self) -> Settings:
        """The settings of the proxy: one thread or worker per CPU it has, and the overrides of the
        variant being measured."""
        settings = Settings(threads=len(self.layout.proxy))
        for name, value in self.overrides.items():
            setattr(settings, name, value)
        return settings

    def out(self, scenario: int, proxy: Proxy) -> Path:
        """The directory of the results of `scenario` for `proxy` in the current variant."""
        name = proxy.kind + (f"-{self.variant}" if self.variant else "")
        return self.work.root / "results" / f"scenario-{scenario}" / name


def wormway_binary(path: str | None) -> Path:
    """The Wormway to measure: `path`, else the system build of `build`, else the release build."""
    for candidate in (Path(path) if path else None, BINARIES / "wormway-system", REPO / "target/release/wormway"):
        if candidate and candidate.exists():
            return candidate.resolve()
    sys.exit("no Wormway binary: run `bench.py build`, or give --wormway")


def command_run(args: argparse.Namespace) -> None:
    """Runs the scenarios for each proxy, then the variants of Wormway, and writes the summary."""
    check_tools()
    open_files = raise_open_files()
    layout = Layout.detect()
    if args.proxy_cpus:
        proxy_cpus = parse_cpus(args.proxy_cpus)
        others = [cpu for cpu in sorted(os.sched_getaffinity(0)) if cpu not in proxy_cpus]
        layout = Layout(proxy=proxy_cpus, tools=parse_cpus(args.tool_cpus) if args.tool_cpus else others)
    out = Path(args.out) if args.out else HERE / "results" / time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    work = Work(out, nginx_version(), open_files)
    work.prepare()
    options = Options(
        warmup=args.warmup,
        duration=args.duration if args.duration else (10.0 if args.quick else 30.0),
        repeats=args.repeats if args.repeats else (1 if args.quick else 3),
        quick=args.quick,
    )
    run = Run(work, layout, options)
    binary = wormway_binary(args.wormway)
    (out / "env.txt").write_text(subprocess.run([str(HERE / "env.sh")], capture_output=True, text=True,
                                                cwd=REPO).stdout)
    (out / "run.json").write_text(json.dumps({
        "args": vars(args), "proxy_cpus": layout.proxy, "tool_cpus": layout.tools, "wormway": str(binary),
        "nginx": ".".join(map(str, work.nginx)),
        "oha": subprocess.run(["oha", "--version"], capture_output=True, text=True).stdout.strip(),
    }, indent=1))
    print(f"results in {out}; proxy on CPUs {layout.proxy}, load and upstream on {layout.tools}", flush=True)
    upstreams = start_upstreams(work, layout)
    try:
        scenarios = [int(number) for number in args.scenarios.split(",")] if args.scenarios else list(SCENARIOS)
        proxies = args.proxies.split(",")
        for number in scenarios:
            for kind in proxies:
                print(f"scenario {number}: {SCENARIOS[number].__doc__.splitlines()[0]} ({kind})", flush=True)
                proxy = Proxy(kind, binary if kind == "wormway" else None, work, layout)
                try:
                    SCENARIOS[number](proxy, run)
                finally:
                    proxy.stop()
        if args.variants and "wormway" in proxies:
            print("variants of Wormway", flush=True)
            variants(run, Proxy("wormway", binary, work, layout), scenarios)
    finally:
        for process in upstreams:
            process.stop()
        Process.stop_all()
    summary = summarize(out)
    (out / "summary.md").write_text(summary)
    print(summary)
    print(f"done: send {out.name}.tar.gz, made with: tar czf {out.name}.tar.gz -C {out.parent} {out.name}")


def parse_cpus(text: str) -> list[int]:
    """CPUs written as 0,1 or 0-3."""
    cpus: list[int] = []
    for part in filter(None, text.split(",")):
        first, _, last = part.partition("-")
        cpus.extend(range(int(first), int(last or first) + 1))
    return cpus


def command_build(_: argparse.Namespace) -> None:
    """Builds the release binary once per allocator, into target/bench/."""
    BINARIES.mkdir(parents=True, exist_ok=True)
    for name in ALLOCATORS:
        features = [] if name == "system" else ["--features", name]
        print(f"building with the {name} allocator", flush=True)
        built = subprocess.run(["cargo", "build", "--release", "--locked", "-p", "wormway", *features], cwd=REPO)
        if built.returncode != 0:
            sys.exit(f"cargo build failed with the {name} allocator; see its output above and the build "
                     "tools in benches/README.md")
        shutil.copy2(REPO / "target/release/wormway", BINARIES / f"wormway-{name}")
    print(f"binaries in {BINARIES}")


def command_configs(args: argparse.Namespace) -> None:
    """Writes the configurations of the proxies and the upstream, to read or check them."""
    work = Work(Path(args.dir), nginx_version() if shutil.which("nginx") else (1, 28, 0))
    work.root.mkdir(parents=True, exist_ok=True)
    work.path("wormway.toml").write_text(wormway_config(work, Settings()))
    all_features = Settings(features=("headers", "ratelimit", "apikey", "accesslog-json"),
                            targets=(UPSTREAM_PORT, SECOND_UPSTREAM_PORT))
    work.path("wormway-features.toml").write_text(wormway_config(work, all_features))
    work.path("wormway-h2.toml").write_text(wormway_config(work, Settings(upstream_protocol="h2")))
    work.path("nginx.conf").write_text(nginx_proxy_config(work, Settings()))
    work.path("nginx-features.conf").write_text(nginx_proxy_config(work, all_features))
    work.path("upstream.conf").write_text(upstream_config(work, "upstream", UPSTREAM_PORT, True))
    print(f"configurations in {work.root}")


def command_soak(args: argparse.Namespace) -> None:
    """Loads Wormway at a steady rate for hours and records its memory every minute, to compare
    allocators over a long run."""
    check_tools()
    open_files = raise_open_files()
    layout = Layout.detect()
    out = Path(args.out) if args.out else HERE / "results" / ("soak-" + time.strftime("%Y%m%dT%H%M%SZ",
                                                                                       time.gmtime()))
    work = Work(out, nginx_version(), open_files)
    work.prepare()
    upstreams = start_upstreams(work, layout)
    proxy = Proxy("wormway", wormway_binary(args.wormway), work, layout)
    try:
        proxy.start(Settings(threads=len(layout.proxy)))
        end = time.monotonic() + args.hours * 3600
        load = run_oha(layout, Load(f"{HTTP}/"), args.rate, args.hours * 3600 + 60, None)
        with open(out / "soak.csv", "w") as csv:
            csv.write("minute,rss_bytes,cpu_seconds\n")
            minute = 0
            while time.monotonic() < end and load.poll() is None:
                usage = Usage.of(proxy.pid)
                csv.write(f"{minute},{usage.rss_bytes},{usage.cpu_seconds:.1f}\n")
                csv.flush()
                minute += 1
                time.sleep(60)
        load.terminate()
    finally:
        proxy.stop()
        for process in upstreams:
            process.stop()
        Process.stop_all()
    print(f"memory over time in {out / 'soak.csv'}")


# ---- Summary ----


def summarize(out: Path) -> str:
    """Markdown tables of the medians of the repeats of a run."""
    lines = [f"# Results of {out.name}", ""]
    env = out / "env.txt"
    if env.exists():
        lines += ["```", env.read_text().strip(), "```", ""]
    results = out / "results"
    for scenario in sorted(results.glob("scenario-*"), key=lambda path: int(path.name.split("-")[1])):
        number = int(scenario.name.split("-")[1])
        lines += [f"## Scenario {number}: {SCENARIOS[number].__doc__.splitlines()[0]}", ""]
        if number == 5:
            lines += memory_table(scenario)
        else:
            lines += load_table(scenario, number)
        lines.append("")
    return "\n".join(lines)


def load_table(scenario: Path, number: int) -> list[str]:
    """One row per proxy, variant and rate: medians of the repeats."""
    rows = ["| proxy | rate | achieved/s | p50 ms | p99 ms | p99.9 ms | max ms | errors | CPU | CPU s per 10k | "
            "RSS MiB | upstream req/conn | accept queue drops |",
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    groups: dict[tuple[str, float], list[dict]] = {}
    for record in sorted(scenario.rglob("*.json")):
        if record.name.endswith(".oha.json"):
            continue
        result = json.loads(record.read_text())
        name = str(record.parent.relative_to(scenario))
        groups.setdefault((name, result["rate"]), []).append(result)
    for (name, rate), results in sorted(groups.items()):
        def median(pick) -> float:
            """The median of `pick` over the repeats that have it."""
            values = [value for value in map(pick, results) if value is not None]
            return statistics.median(values) if values else float("nan")

        def percentile(key: str) -> float:
            """A latency percentile in milliseconds."""
            return median(lambda r: (r.get("oha") or {}).get("latencyPercentiles", {}).get(key)) * 1000

        achieved = median(lambda r: outcome(r)[0])
        errors = median(lambda r: outcome(r)[2])
        slowest = median(lambda r: (r.get("oha") or {}).get("summary", {}).get("slowest")) * 1000
        cpu = median(lambda r: r["cpu_seconds"] / r["wall_seconds"])
        per_10k = median(lambda r: r["cpu_seconds"] / (outcome(r)[0] * r["wall_seconds"]) * 10000
                         if outcome(r)[0] else None)
        rss = median(lambda r: r["rss_bytes"]) / (1 << 20)
        reuse = median(lambda r: r["upstream_requests"] / r["upstream_connections"]
                       if r.get("upstream_connections") else None)
        drops = median(lambda r: r["listen_queue"].get("ListenDrops", 0))
        extra = f" ({results[0].get('reloads')} reloads)" if results[0].get("reloads") else ""
        rows.append(f"| {name}{extra} | {rate:.0f} | {achieved:.0f} | {percentile('p50'):.2f} | "
                    f"{percentile('p99'):.2f} | {percentile('p99.9'):.2f} | {slowest:.1f} | {errors:.2%} | "
                    f"{cpu:.0%} | {per_10k:.3f} | {rss:.1f} | {reuse:.0f} | {drops:.0f} |")
    return rows


def memory_table(scenario: Path) -> list[str]:
    """One row per proxy and variant: connections held and the memory they took."""
    rows = ["| proxy | connections | RSS before MiB | RSS held MiB | KiB per connection |",
            "|---|---|---|---|---|"]
    for directory in sorted(path for path in scenario.iterdir() if path.is_dir()):
        results = [json.loads(path.read_text()) for path in sorted(directory.glob("*.json"))]
        if not results:
            continue
        per = [r["per_connection_bytes"] for r in results if r["per_connection_bytes"] is not None]
        rows.append(f"| {directory.name} | {statistics.median(r['connections'] for r in results):.0f} | "
                    f"{statistics.median(r['base_rss_bytes'] for r in results) / (1 << 20):.1f} | "
                    f"{statistics.median(r['held_rss_bytes'] for r in results) / (1 << 20):.1f} | "
                    f"{(statistics.median(per) / 1024) if per else float('nan'):.1f} |")
    return rows


# ---- WebSocket helpers of scenario 5 ----


async def ws_upstream(port: int) -> None:
    """Answers every request with 101 Switching Protocols, then sends back what it receives."""

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Serves one connection."""
        try:
            await reader.readuntil(b"\r\n\r\n")
            writer.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
            await writer.drain()
            while data := await reader.read(65536):
                writer.write(data)
                await writer.drain()
        except (OSError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", port, backlog=4096)
    async with server:
        await server.serve_forever()


async def ws_clients(port: int, count: int) -> None:
    """Opens `count` WebSocket connections through the proxy on loopback `port`, prints `ready N`
    once they are open, and holds them until standard input closes."""
    writers: list[asyncio.StreamWriter] = []
    failures: list[str] = []
    request = (b"GET /ws HTTP/1.1\r\nHost: bench.local\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
               b"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")

    async def open_one() -> None:
        """Opens one connection and waits for its 101."""
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        writer.write(request)
        await writer.drain()
        head = await reader.readuntil(b"\r\n\r\n")
        if not head.startswith(b"HTTP/1.1 101"):
            writer.close()
            raise ConnectionError(head.split(b"\r\n")[0].decode(errors="replace"))
        writers.append(writer)

    async def open_in_time() -> None:
        """Opens one connection within 30 seconds, or notes why not."""
        try:
            await asyncio.wait_for(open_one(), 30)
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError) as error:
            failures.append(repr(error))

    # In batches, so that the accept queues of the proxy and the upstream keep up.
    for start in range(0, count, 100):
        await asyncio.gather(*(open_in_time() for _ in range(min(100, count - start))))
    print(f"ready {len(writers)}", flush=True)
    if failures:
        print(f"{len(failures)} failed, such as {failures[0]}", file=sys.stderr, flush=True)
    await asyncio.get_running_loop().run_in_executor(None, sys.stdin.read)
    for writer in writers:
        writer.close()


# ---- Command line ----


def main() -> None:
    """Parses the command line and runs the command."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="run the scenarios")
    run.add_argument("--quick", action="store_true", help="fewer rates, one 10-second run each")
    run.add_argument("--scenarios", help="such as 1,3,5; all by default")
    run.add_argument("--proxies", default="wormway,nginx", help="wormway, nginx or both (default)")
    run.add_argument("--no-variants", dest="variants", action="store_false",
                     help="skip the variants of Wormway (allocators, backlog, pool, upstream HTTP/2)")
    run.add_argument("--wormway", help="the binary to measure; default target/bench/wormway-system")
    run.add_argument("--warmup", type=float, default=5.0, help="seconds of warm-up before each run")
    run.add_argument("--duration", type=float, help="seconds of each run; 30, or 10 with --quick")
    run.add_argument("--repeats", type=int, help="runs of each measurement; 3, or 1 with --quick")
    run.add_argument("--proxy-cpus", help="CPUs of the proxy, such as 1 or 2-3; the upper half by default")
    run.add_argument("--tool-cpus", help="CPUs of the load generator and the upstream")
    run.add_argument("--out", help="directory of the results; benches/results/<time> by default")
    commands.add_parser("build", help="build the release binary once per allocator")
    summary = commands.add_parser("summarize", help="print the tables of a run")
    summary.add_argument("dir")
    configs = commands.add_parser("configs", help="write the configurations to a directory")
    configs.add_argument("dir")
    soak = commands.add_parser("soak", help="load Wormway for hours and record its memory")
    soak.add_argument("--hours", type=float, default=24)
    soak.add_argument("--rate", type=float, default=5000)
    soak.add_argument("--wormway")
    soak.add_argument("--out")
    upstream = commands.add_parser("ws-upstream")
    upstream.add_argument("port", type=int)
    clients = commands.add_parser("ws-clients")
    clients.add_argument("port", type=int)
    clients.add_argument("count", type=int)
    args = parser.parse_args()

    if args.command == "ws-upstream":
        asyncio.run(ws_upstream(args.port))
        return
    if args.command == "ws-clients":
        raise_open_files()
        asyncio.run(ws_clients(args.port, args.count))
        return
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(1))
    try:
        {"run": command_run, "build": command_build, "configs": command_configs, "soak": command_soak,
         "summarize": lambda a: print(summarize(Path(a.dir)))}[args.command](args)
    except KeyboardInterrupt:
        sys.exit(1)
    finally:
        Process.stop_all()


if __name__ == "__main__":
    main()
