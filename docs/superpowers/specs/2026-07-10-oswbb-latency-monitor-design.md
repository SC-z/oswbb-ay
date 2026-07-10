# OSWbb 3-Node Latency Monitor Design

## Goal

Add long-running ICMP latency collection for a three-node Linux cluster while preserving the existing OSWbb collection architecture. Every node measures both remote nodes with a 56-byte payload and an 8192-byte payload on every OSWbb snapshot interval. `oswbb-analyse` reads the archived results and reports long-term latency and loss statistics.

## Packet Semantics

- `56` and `8192` are ICMP payload sizes passed to `ping -s`.
- The 56-byte probe is the normal small-packet baseline.
- With MTU 1500, the 8192-byte probe is fragmented at IPv4 and reassembled by the destination. It therefore measures the fragmented large-message path, not one jumbo Ethernet frame.
- The large probe must not use `-M do`, because that would reject an 8192-byte payload on an MTU-1500 path instead of measuring it.
- Collection uses one probe per target and size per OSWbb interval. Long-running percentiles are calculated from the accumulated samples.

## Collection Architecture

The implementation follows the same pattern as the existing `vmstat`, `iostat`, `top`, and other OSWbb collectors:

1. `OSWatcher.sh` detects `ping`, creates `archive/oswlatency`, manages a `latencylock.file`, creates hourly files, compresses the previous hour, and invokes a dedicated child collector.
2. `latencysub.sh` writes one timestamped collection block to the hourly file, probes every configured peer at both payload sizes, records a structured result line, and always releases its lock.
3. `OSWatcherFM.sh` applies the configured hourly retention policy to `archive/oswlatency` exactly as it does for the existing archive directories.
4. `stopOSWbb.sh` needs no separate daemon handling because the collector remains a bounded child of the OSWatcher loop.

No standalone service, cron job, `fping` dependency, or alternate retention mechanism is introduced.

## Target Configuration

Each node has an `oswlatency.conf` file in the OSWbb installation directory. Each non-comment line contains a stable node name and an IPv4 address separated by whitespace:

```text
node2 10.0.0.12
node3 10.0.0.13
```

Each node lists only its two remote peers. This produces six directed paths across the cluster and avoids meaningless loopback samples. Blank lines and lines beginning with `#` are ignored. Invalid lines are logged as collection errors without stopping valid targets.

## Probe Execution And Archive Format

The Linux collector runs the equivalent of:

```sh
ping -n -c 1 -W 1 -s 56 TARGET
ping -n -c 1 -W 1 -s 8192 TARGET
```

It inherits OSWbb's `LC_ALL=C`. Every attempt emits one machine-readable line while retaining the raw command output for operator inspection:

```text
OSWLATENCY|timestamp=2026-07-10T12:00:00+0800|source=node1|target=node2|address=10.0.0.12|size=56|status=ok|rtt_ms=0.183
OSWLATENCY|timestamp=2026-07-10T12:00:01+0800|source=node1|target=node2|address=10.0.0.12|size=8192|status=timeout|rtt_ms=
```

Supported statuses are `ok`, `timeout`, `config_error`, and `ping_error`. A missing `ping` binary disables only this collector and produces an explicit OSWatcher warning.

## Offline Analysis

`oswbb-analyse` gains a latency file type and module following the current module registry and report pipeline. It recognizes hourly files under `oswlatency` by filename, parses only `OSWLATENCY|` records, and groups data by source, target, address, and payload size.

For each directed path and size, reports contain:

- attempted and successful samples;
- loss count and loss percentage;
- minimum, average, maximum, P50, P95, and P99 RTT;
- first and last sample timestamps.

For each directed path, the report also shows the 8192-byte versus 56-byte average and P95 difference and ratio. If small probes succeed while large probes fail, the report labels it as a fragmented-large-packet path failure and recommends checking fragmentation filtering, reassembly limits, and path behavior. It does not claim that MTU 1500 alone is a fault.

Report, CSV, JSON, and HTML outputs reuse the existing output pipeline. No environment-specific absolute latency threshold is hard-coded; the feature reports measured values and the directly supported small-versus-large comparison.

## Error Handling

- The child collector has a bounded one-second timeout per probe and releases the OSWbb lock through a shell trap.
- One failed target or size does not prevent the remaining probes.
- A missing or empty configuration produces an explicit archive record and releases the lock.
- Malformed structured records are skipped by the analyzer and surfaced as diagnostics; valid records in the same file remain usable.
- Gzip-compressed hourly files continue through the existing archive processing path.

## Tests

Implementation follows red-test-first development:

1. Shell tests use a fake `ping` in `PATH` to prove that each configured peer is probed once with size 56 and once with size 8192, and that success, timeout, malformed configuration, and lock cleanup are recorded correctly.
2. Parser tests cover successful samples, timeouts, malformed lines, mixed raw output, multiple nodes, and compressed hourly fixtures.
3. Analyzer tests verify loss calculations, percentile boundaries, directed-path grouping, and 56-versus-8192 comparison.
4. Registry and path-detection tests prove an OSWbb archive root automatically discovers the new module without changing existing module behavior.
5. Focused tests are followed by `GOCACHE=/private/tmp/oswbb-ay-go-build go test ./...` and shell syntax checks.

## Three-Node Acceptance

The feature is complete only when all three nodes run the modified OSWbb collector with two peer entries each and current archive evidence proves:

- every node produces hourly `oswlatency` files;
- all six directed paths contain both size 56 and size 8192 records over multiple intervals;
- hourly compression and configured retention work;
- `oswbb-analyse` reads the collected archive and reports both packet sizes, loss, percentiles, and small-versus-large comparison;
- collector failures do not stop the existing OSWbb modules.

Node addresses and remote access are deployment inputs, not values embedded in the implementation.
