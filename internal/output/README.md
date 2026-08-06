# internal/output

Unified report rendering for `internal/report.Report`.

- `TextFormatter` renders shared text report sections.
- `JSONFormatter` renders the same report object as indented JSON.
- `HTMLFormatter` renders generic report HTML, and can preserve the legacy
  chart dashboard when report metadata provides raw chart data.
- `CSVFormatter` renders a selected structured `report.Table`.

`pkg/output` remains a compatibility layer for older callers. The main
iostat/meminfo/top HTML and CSV export paths now build `internal/report.Report`
and format through this package.
