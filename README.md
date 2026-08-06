# OSWbb Analyse

[简体中文](README.zh-CN.md)

`oswbb-analyse` is an offline analyzer for archives produced by **Oracle OSWatcher / OSWbb**. It helps DBAs and Linux operators turn OSWbb `iostat`, `meminfo`, `top`, and `mpstat` logs into repeatable findings and text, CSV, JSON, or HTML reports.

> This project analyzes OSWbb output; it is **not** Oracle OSWbb and does not include, distribute, modify, or install Oracle's OSWbb scripts or binaries. Obtain and run OSWbb separately through Oracle's supported distribution channels, then pass its archive directory to this tool. This project is not affiliated with or endorsed by Oracle.

## What it analyzes

- **iostat**: IOPS, throughput, latency, queue depth, utilization, and abnormal latency candidates.
- **meminfo**: available memory, anonymous-page growth, swap, commit pressure, slab, dirty, and writeback signals.
- **top**: load, CPU user/system/idle/iowait/steal, process states, and representative process candidates.
- **mpstat**: CPU-count metadata used to normalize `top` load and runnable-task signals.

The analyzer recursively discovers compatible OSWbb archive directories, reads `.gz` archives without rewriting the original log, and merges time ranges belonging to the same host.

## Quick start

Requirements: Go 1.23 or newer. The checked-in `go.mod` specifies the exact toolchain used by the project.

```bash
git clone https://github.com/SC-z/oswbb-ay.git
cd oswbb-ay

# Build the deterministic rules-based analyzer.
make build

# Run it against an OSWbb archive root.
./oswbb-analyse -f /path/to/oswbb/archive
```

The rules-based command does not require a model runtime. It is the recommended default for reproducible operational analysis.

## Common commands

```bash
# Generate an interactive HTML report.
./oswbb-analyse -f /path/to/oswbb/archive -o html

# Export parsed iostat data.
./oswbb-analyse -f /path/to/oswbb/archive/oswiostat -o csv

# Restrict analysis to a known incident window.
./oswbb-analyse -f /path/to/oswbb/archive \
  -start "2025-12-17 09:00:00" \
  -end "2025-12-17 10:00:00"

# Use threshold overrides from a TOML file.
./oswbb-analyse -f /path/to/oswbb/archive -config configs/default.toml
```

`-start` and `-end` must be supplied together. When neither is supplied, the complete time range available in each log is analyzed.

## Output formats

| Format | Purpose |
| --- | --- |
| `report` | Default terminal report with findings and supporting details. |
| `csv` | Tabular raw and derived metrics for further analysis. |
| `json` | Structured output for integrations. |
| `html` | Interactive report. ECharts is loaded from a CDN, so use `report`, `csv`, or `json` for fully offline environments. |
| `ml` | Rules-based binary: CSV-compatible export. AI binary: local-model analysis workflow. |

Generated filenames include the module, host name when available, and a high-precision timestamp to avoid collisions across hosts.

## Optional local AI analysis

The separate AI command keeps the default analyzer free of local-model dependencies:

```bash
make build-ai

./oswbb-analyse-ai -f /path/to/oswbb/archive \
  --ai-runtime-path /opt/llama.cpp/llama-cli \
  --ai-model-path /opt/models/Qwen3-0.6B-Q8_0.gguf \
  --ai-timeout 180s
```

The AI command defaults to `-o ml`: it writes an ML-oriented CSV first, then submits ordered rows to a locally configured runtime. If that runtime is unavailable or its output cannot be validated, the command reports the fallback reason and retains the rules-based findings. No cloud model service is required by this repository.

## Configuration and testing

- [`configs/default.toml`](configs/default.toml) documents the default thresholds.
- `make test` runs the Go test suite.
- A few regression tests can use large, local real-world OSWbb archives. They run when the optional archive is available and are skipped in a clean checkout where it is absent; the tracked synthetic tests always run.

## Scope and data handling

OSWbb archives can contain host names, process details, and operationally sensitive information. Do not commit customer archives or reports. This tool analyzes existing archives only; it does not start, stop, configure, or modify an OSWbb collection.

For a standard-library operational analyzer and archive-coverage workflow, see [`skills/oswbb-ops`](skills/oswbb-ops/).
