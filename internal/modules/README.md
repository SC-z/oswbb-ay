# internal/modules

Module-specific parser/analyzer/report-object packages live here while the
legacy CLI flow remains under `pkg/processor`.

`module.go` defines only small boundary interfaces. It deliberately avoids a
plugin registry so `pkg/iostat`, `pkg/meminfo`, and `pkg/top` can migrate one
module at a time without changing the public CLI contract.
