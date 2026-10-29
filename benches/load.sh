#!/usr/bin/env bash
# Sends HTTP requests at a fixed rate and records the latency distribution.
#
#   benches/load.sh URL RATE [DURATION] [CONNECTIONS]
#
# RATE is requests per second; DURATION defaults to 30s and CONNECTIONS to 64. Latencies are
# measured from when each request was due, so stalls of the server are not hidden. The report
# and the environment go to benches/results/<time>/.
set -euo pipefail

if [ $# -lt 2 ]; then
    sed -n '4,8p' "$0" >&2
    exit 2
fi
url=$1
rate=$2
duration=${3:-30s}
connections=${4:-64}
if ! command -v oha >/dev/null; then
    echo "oha is required: https://github.com/hatoo/oha" >&2
    exit 1
fi

here=$(cd "$(dirname "$0")" && pwd)
dir="$here/results/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$dir"
"$here/env.sh" >"$dir/env.txt"
echo "url: $url, rate: $rate/s, duration: $duration, connections: $connections" | tee "$dir/run.txt"

echo "warming up for 5s"
oha --no-tui -q "$rate" -z 5s -c "$connections" "$url" >/dev/null
echo "measuring for $duration"
oha --no-tui --latency-correction -q "$rate" -z "$duration" -c "$connections" \
    --output-format json -o "$dir/report.json" "$url"
echo "results in $dir"
