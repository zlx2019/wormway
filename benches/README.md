# Benchmarks

How the performance of zora is measured. Scenarios arrive with the features they measure,
starting with the gateway; this directory holds the method and the scripts they share.

## Method

- **Open loop.** Send requests at a fixed rate, whatever the server does, and measure each
  latency from when the request was due. A closed-loop tool, where each connection sends its
  next request only after the last answer, slows down with the server and hides its stalls
  (coordinated omission).
- **Whole latency distributions.** Report p50, p90, p99, p99.9 and the maximum rather than
  averages. Compare runs at the same rate, and look for the highest rate that still meets a
  latency target rather than for the highest throughput.
- **Warm up, then measure.** Discard a short warm-up, measure for at least 30 seconds, repeat
  every run at least three times and report the spread.
- **Separate machines.** The load generator and zora should not share CPUs. On one machine,
  pin them to different cores (`taskset` on Linux) and say so next to the results.
- **Release builds.** `cargo build --release` uses fat LTO and one codegen unit.
- **Record the environment** with every result: hardware, operating system, kernel settings,
  Rust version and commit. `env.sh` prints them.

## Scripts

| Script | Purpose |
|---|---|
| `env.sh` | Prints the environment of a run. |
| `load.sh URL RATE [DURATION] [CONNECTIONS]` | Warms up, then sends HTTP requests to `URL` at `RATE` per second with [oha](https://github.com/hatoo/oha), and saves the latency report and the environment in `results/`. |

`results/` is not committed. On Linux, also check the limits that cap a load test before zora
does: `ulimit -n`, `net.core.somaxconn`, `net.ipv4.tcp_max_syn_backlog` and
`net.ipv4.ip_local_port_range`; `env.sh` prints them.
