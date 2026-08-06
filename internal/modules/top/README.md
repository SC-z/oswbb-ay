# internal/modules/top

The top module boundary wraps the existing `pkg/top` parser and `pkg/findings`
judgement logic.

- `parser.go` parses a list of already-classified top files and returns
  `ParsedData`.
- `analyzer.go` converts `ParsedData` into `Analysis` by reusing
  `findings.BuildTopFindings`.
- `report.go` builds a module-local report object only; it does not replace the
  current text/html/csv/json output layer.

This package must not redefine CPU, load, process, runnable, zombie, or steal
thresholds or print reports directly. Those behaviours remain in the legacy
packages until the output layer is migrated explicitly.
