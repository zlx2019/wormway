#!/usr/bin/env bash
# Prints the environment a benchmark runs in, to keep next to its results.
set -euo pipefail

echo "date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
commit=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)
if ! git diff --quiet HEAD 2>/dev/null; then
    commit="$commit (with uncommitted changes)"
fi
echo "commit: $commit"
echo "os: $(uname -srm)"
echo "rustc: $(rustc --version 2>/dev/null || echo unknown)"

# Prints the first line of what a tool says about its version, or that it is not installed.
version() {
    if command -v "$1" >/dev/null; then "$@" 2>&1 | head -n 1; else echo "not installed"; fi
}
echo "nginx: $(version nginx -v)"
echo "oha: $(version oha --version)"
echo "python: $(version python3 --version)"
echo "openssl: $(version openssl version)"
echo "perf: $(version perf --version)"

case "$(uname -s)" in
    Linux)
        echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
        echo "cores: $(nproc)"
        # The CPUs that share a core, whose hyperthreads compete for its execution units.
        siblings=$(cat /sys/devices/system/cpu/cpu[0-9]*/topology/thread_siblings_list 2>/dev/null \
            | sort -u | paste -sd ' ' - || true)
        echo "hyperthread siblings: ${siblings:-unknown}"
        echo "memory: $(free -h | awk '/^Mem:/ {print $2}')"
        echo "cpu governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)"
        echo "swap: $(free -h | awk '/^Swap:/ {print $2}')"
        echo "transparent huge pages: $(cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || echo unknown)"
        for key in net.core.somaxconn net.ipv4.tcp_max_syn_backlog net.ipv4.ip_local_port_range \
            net.ipv4.tcp_tw_reuse kernel.perf_event_paranoid kernel.kptr_restrict; do
            echo "$key: $(sysctl -n "$key" 2>/dev/null | tr '\t' ' ' || echo unknown)"
        done
        ;;
    Darwin)
        echo "cpu: $(sysctl -n machdep.cpu.brand_string)"
        echo "cores: $(sysctl -n hw.ncpu)"
        echo "memory: $(($(sysctl -n hw.memsize) / 1073741824)) GiB"
        for key in kern.ipc.somaxconn net.inet.ip.portrange.first net.inet.ip.portrange.last; do
            echo "$key: $(sysctl -n "$key")"
        done
        ;;
esac
echo "open files limit: $(ulimit -n)"
