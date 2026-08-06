# internal/modules/meminfo

The meminfo module boundary wraps the existing `pkg/meminfo` parser and
`pkg/findings` judgement logic.

- `parser.go` parses a list of already-classified meminfo files and returns
  `ParsedData`.
- `analyzer.go` converts `ParsedData` into `Analysis` by reusing
  `findings.BuildMemInfoFindings`.
- `report.go` builds a module-local report object only; it does not replace the
  current text/html/csv/json output layer.

This package must not redefine memory, swap, slab, or anon-growth thresholds or
print reports directly. Those behaviours remain in the legacy packages until
the output layer is migrated explicitly.
