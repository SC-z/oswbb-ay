# Analysis Threshold Configuration

The effective configuration order is:

```text
built-in defaults < config file < existing explicit CLI flags
```

When `--config` is omitted, `config.Default()` keeps the legacy thresholds and report behavior.
When `--config` is provided, the file must exist. Unknown keys, invalid types, invalid percentages, negative sizes, and conflicting soft/hard bounds fail before analysis starts.

## Example

```toml
[iostat]
cpu_wait_soft_pct = 12
cpu_wait_hard_pct = 25

[meminfo]
available_warn_pct = 25

[top]
load_per_cpu_soft = 0.9
```

Partial files override only the specified keys; all other values remain at defaults.

## Defaults

See `configs/default.toml` for the full key list. Units are encoded in key names:

- `_pct`: percent, valid range `0..100`.
- `_ms`: milliseconds, positive.
- `_mb`: MiB, positive.
- `_points` and `_samples`: sample counts, positive integers.
- `load_*`, `queue_*`, and `runnable_*`: unitless analyzer thresholds, positive.

Existing explicit CLI flags still win over config where they already exist:

- `-o` or trailing `-o` output selection overrides `general.default_output_format` or `ai.default_output_format`.
- `--ai-timeout` overrides `ai.timeout_seconds`.
