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

case "$(uname -s)" in
    Linux)
        echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
        echo "cores: $(nproc)"
        echo "memory: $(free -h | awk '/^Mem:/ {print $2}')"
        echo "cpu governor: $(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)"
        for key in net.core.somaxconn net.ipv4.tcp_max_syn_backlog net.ipv4.ip_local_port_range \
            net.ipv4.tcp_tw_reuse; do
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
