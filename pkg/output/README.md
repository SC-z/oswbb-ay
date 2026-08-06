# pkg/output compatibility boundary

`pkg/output` is a legacy adapter package.

New code should format `internal/report.Report` with `internal/output`.

## Adapter APIs

- `CreateFormatter`
- `OutputFormatter`
- `NewCSVFormatter`, `NewJSONFormatter`, `NewHTMLFormatter`
- `CSVFormatter.Output*Data`
- `JSONFormatter.Output*Data`
- `HTMLFormatter.Output*Data`
- `FormatIOStatCSV`, `FormatMemInfoCSV`, `FormatTopCSV`

These APIs are kept for legacy processor callers, the old JSON envelope, the
HTML dashboard compatibility path, and AI CSV prompt input.

## Structured helper APIs still in use

- `ConvertIOStatData`, `ConvertMemInfoData`, `ConvertTopData`
- `IOStatRawMetricsTable`, `MemInfoRawMetricsTable`, `TopRawMetricsTable`
- raw metrics/export structs used by legacy JSON, HTML, CSV, and AI paths

## Deletion prerequisites

1. Processor legacy export paths no longer call `OutputFormatter`.
2. AI CSV prompt input no longer depends on raw metric exports.
3. HTML dashboard compatibility is either migrated or explicitly removed.
4. Tests cover the replacement schema and old envelope removal.
