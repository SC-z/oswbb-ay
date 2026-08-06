# iostat strategy

## Purpose

Use active I/O samples only. Never treat `await`, queue, or utilization values from an idle device as pressure.

## Current thresholds

| Signal | Soft | Hard |
| --- | ---: | ---: |
| Queue depth | 0.3 | 1.0 |
| CPU iowait | 10% | 20% |
| Active IOPS corroboration | 10 | — |
| Utilization | 80% | 95% |
| Utilization minimum samples | 3 | 3 |
| NVMe latency | 6 ms | 8 ms |
| Other/upper-layer latency | 37.5 ms | 50 ms |
| Z-score | — | 3 |
| MAD score | — | 3 |
| IQR multiplier | — | 1.5 |

Apply read, write, and discard latency separately. Include discard IOPS in total activity.

## Evidence gates

- Treat latency as risk when the same sample has at least 10 IOPS, queue depth at least 0.3, or iowait at least 10%.
- Keep an uncorroborated absolute latency threshold crossing as a candidate.
- Suppress a soft P95 latency finding unless a matching high-latency sample has IOPS, queue, or iowait support.
- Report a single queue peak only when it reaches the hard threshold and has iowait or at least 10 IOPS. Report sustained active queue pressure when multiple active samples support it.
- Require at least three active samples for utilization. Keep sustained hard utilization without latency/queue/iowait support as a candidate.
- Treat `dm-*`, `md*`, `mpath*`, LVM, and similar stacked devices carefully. Do not count a stacked and physical view of the same event as independent evidence.
- Promote multi-device latency only when at least two physical/storage devices show the same direction in the same timestamp and queue or iowait supports shared pressure.

## Operations interpretation

- High latency with low queue and low iowait: device/path slow request candidate, not system saturation.
- High latency plus queue or iowait: storage pressure risk.
- Multi-device aligned latency: shared path, controller, backend, or host-wide I/O pressure.
- High utilization alone: busy device candidate; distinguish healthy sequential throughput from latency pressure.
