# Rule snapshot provenance

Snapshot date: 2026-07-24

The Skill is self-contained and does not read these source files at runtime. Refresh the Skill only through an explicit update and parity test.

| Source file | SHA-256 |
| --- | --- |
| `internal/config/defaults.go` | `bf548bb7586cfbda35bde1c519a2a7af3aac849c340885033ae98ed73219993e` |
| `pkg/iostat/iostat.go` | `c6d5533b8fd323c43c7cda2cf81d23118ad77a8815bd6551e988bb2a24141c87` |
| `pkg/findings/iostat.go` | `56300c4e4ee6affc90d21c5a1b4009d254c825389c2d324d8e4b05fa759fa55c` |
| `pkg/meminfo/meminfo.go` | `69832e7074ea3c708d3b3a7d7a95df9d15385a575518c68ec1a3b8da433d1818` |
| `pkg/findings/meminfo.go` | `d16458fdc68340b686a2a89cf3ea3a6c2ebd615eb534da25633557aa169b12ff` |
| `pkg/top/top.go` | `12ae4e968ec0c482bea0746317fa712c05d17c854be768e531e72966ec25a7a3` |
| `pkg/top/types.go` | `dfbde801ad0a4a8393fdfbfd8bbd8bc1769aeaa31d98825ff5853496cda95f8a` |
| `pkg/findings/top.go` | `f5ae33c880d324138a9367b027cf635158ef4359f898c02ff3c3e36a6528f86b` |
| `pkg/processor/mpstat_cpu.go` | `ebbc22b08b3cf4725a9c32b4e56563095e3b3b22ecae77dc575812ddac73f45f` |

Refresh procedure:

1. Re-read every changed source and its behavior tests.
2. Update constants and paired evidence gates together.
3. Update hashes and snapshot date.
4. Run `scripts/oswbb_analyze.py self-check`.
5. Compare representative healthy, isolated-spike, sustained-pressure, recovered-peak, and cross-module fixtures.
6. Forward-test the Skill without exposing expected conclusions.
