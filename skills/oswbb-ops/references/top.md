# top strategy

## Current thresholds

| Signal | Soft | Hard |
| --- | ---: | ---: |
| CPU idle | <=20% | <=10% |
| CPU iowait | >=10% | >=20% |
| CPU steal | >=5% | >=10% |
| Load without CPU count | 4 | 8 |
| Load per CPU | 0.70 | 1.00 |
| Runnable per CPU | 0.70 | — |
| Runnable without CPU count | 8 | — |
| High-idle guard | 80% | — |
| Process CPU | 50% | — |
| Process memory | 5% | — |

Use the target host CPU count from companion mpstat logs. Never use the Agent host's CPU count.

## Evidence gates

- Report low CPU idle when sustained or when the same sample has a high-CPU process or a capacity-aware runnable queue.
- Report a single iowait spike only when the same sample has D-state or runnable-queue evidence. Sustained uncorroborated iowait remains a candidate pending iostat.
- Report single steal spikes as candidates; repeated or average threshold crossings are risks.
- Report high load only when the same high-load window has low idle, sustained iowait, runnable pressure, or D-state tasks.
- High load with high idle and D-state points to blocked/uninterruptible work, not CPU saturation.
- Count D-state concurrency per snapshot. Do not present unique PIDs spread across time as simultaneous process count.
- Report high-CPU processes only during system CPU pressure (`idle <= 20%`).
- A single zombie is low severity; repeated zombies are medium; multiple concurrent zombies are high.

## Operations interpretation

- Low idle plus runnable pressure/high CPU process: CPU saturation.
- High iowait plus D-state and iostat latency/queue: storage wait chain.
- High steal: hypervisor contention.
- High load with high idle and D-state: blocked tasks or storage/network filesystem wait.
