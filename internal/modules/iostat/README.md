# internal/modules/iostat

The iostat module boundary wraps the existing `pkg/iostat` parser and
`pkg/findings` judgement logic.

- `parser.go` parses a list of already-classified iostat files and returns
  `ParsedData`.
- `analyzer.go` converts `ParsedData` into `Analysis` by reusing
  `findings.BuildIOStatFindings`.
- `report.go` builds `internal/report.Report` for the unified text/json
  formatter path.

This package must not redefine await/util/svctm thresholds or print reports
directly. Those behaviours remain in the legacy packages until the output layer
is migrated explicitly.
