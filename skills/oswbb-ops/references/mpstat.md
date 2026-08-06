# mpstat strategy

Use mpstat as capacity and coverage evidence in this Skill version.

1. Parse the first positive `(<N> CPU)` header for each host.
2. Attach that CPU count to top analysis from the same host.
3. Normalize load and runnable thresholds using the target CPU count.
4. If mpstat is absent or malformed, use the legacy absolute top thresholds and report the missing capacity metadata.
5. Never substitute CPU count from the Agent or analysis host.

This version does not emit standalone per-CPU imbalance findings. Add them only with a separately validated parser and rule set.
