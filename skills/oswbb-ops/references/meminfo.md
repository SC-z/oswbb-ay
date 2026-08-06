# meminfo strategy

## Current thresholds

| Signal | Soft | Hard |
| --- | ---: | ---: |
| MemAvailable | <30% | <20%; severe <10% |
| Anon growth | 128 MB | 200 MB |
| Anon growth rate per 5-second sample | 20 MB | 50 MB |
| Anon relative delta | 1% | 5% |
| Swap used | — | 10% |
| Swap growth | 128 MB | — |
| Commit | 90% | 100% |
| Slab absolute | 10 GB | 20 GB |
| Slab ratio | 4% | 8% |
| SUnreclaim ratio | 1% | 2% |
| Dirty ratio | 2% | 5% |
| Writeback ratio | 0.2% | 1% |
| Writeback absolute | 256 MB | 1024 MB |
| Anon window | 36 samples | — |

Use `MemAvailable`; when absent, conservatively use `MemFree + Buffers + Cached + SReclaimable`, capped at `MemTotal`.

## Evidence gates

- Ignore snapshots without `MemTotal` or any independent memory-pressure signal.
- Downgrade one recovered low-available sample to a candidate. Keep current or repeated low availability as risk.
- Never treat missing `SwapFree` as fully used swap. Require a real `SwapTotal` plus present `SwapFree`.
- Keep recovered Swap, Commit, Slab, and Writeback peaks as candidates; current triggers are risks.
- Do not report Dirty alone. Require non-zero Writeback and the paired Dirty/Writeback conditions.
- Prefer SUnreclaim ratio over total Slab size. Large reclaimable Slab on a large host is not automatically a problem.
- Report anonymous growth only when it is sustained or supported by falling availability, growing Swap, or Commit pressure. Keep small relative growth without pressure as a low-confidence candidate.

## Operations interpretation

- Low availability plus Swap or Commit growth: active memory pressure.
- Growing anonymous pages plus falling availability: leak/workload-growth risk; identify processes with top/ps evidence.
- High SUnreclaim: kernel object or unreclaimable slab pressure.
- Dirty plus Writeback accumulation and iowait: writeback/storage bottleneck chain.
