---
name: oswbb-ops
description: Analyze Oracle OSWatcher Black Box (OSWbb) archives and help operators locate Linux performance problems from iostat, meminfo, top, and mpstat evidence. Use when a request mentions OSWbb or OSWatcher logs, archive coverage or gaps, a fault time window, disk latency or queueing, memory pressure, CPU/load/process anomalies, enabling or disabling an OSWbb collection item, or adding a custom OSWatcher collection item. Do not trigger for generic live Linux or SAR analysis without OSWbb context.
---

# OSWbb Operations

Use the bundled standard-library analyzer to extract deterministic evidence. Perform cross-module reasoning only after the script has produced structured results.

## Choose the workflow

- For log diagnosis, follow **Analyze logs**.
- For missing or incomplete coverage, report the gap before diagnosing.
- For collection-item enable/disable or extension, follow **Modify collection**.
- Keep ordinary diagnosis read-only. Never infer permission to stop OSWbb or edit its scripts.

## Analyze logs

1. Resolve the OSWbb archive path and optional host/time window from the request.
2. Respect the available Tools' security boundary. Logs commonly reside on another host:
   - Prefer executing `scripts/oswbb_analyze.py` beside the logs.
   - Do not copy full logs away from the log host unless explicitly authorized.
   - Do not add extra redaction; retain real identifiers and necessary evidence.
   - If remote file placement is unavailable, provide the script invocation for an operator to run and consume the returned JSON.
3. Run inventory first:

   ```bash
   python3 scripts/oswbb_analyze.py inventory /path/to/archive
   ```

4. Check hosts, actual coverage, sample intervals, gaps, parse errors, and available modules. Never treat absent data as healthy.
5. Run analysis:

   ```bash
   python3 scripts/oswbb_analyze.py all /path/to/archive
   ```

   Add `--start "YYYY-MM-DD HH:MM:SS"` and `--end "YYYY-MM-DD HH:MM:SS"` together when a fault window is known. Without a window, analyze all available data.
6. Read only the references for modules present:
   - `references/iostat.md`
   - `references/meminfo.md`
   - `references/top.md`
   - `references/mpstat.md`
7. Correlate findings by host and timestamp. Promote a finding to **confirmed problem** only when direct fault evidence or independent modules support the same failure chain. Keep uncorroborated findings as **risk signal** or **candidate clue**.
8. Return:
   - direct conclusion;
   - host, actual coverage, interval, gaps, and missing modules;
   - confirmed problems;
   - risk signals;
   - candidate clues and data gaps;
   - cross-module timeline;
   - exact evidence and observed values;
   - prioritized next checks.

Do not call or depend on `oswbb-analyse`. The bundled script is the evidence engine. Do not use local-AI runtimes.

## Interpret classifications

- `risk`: the source rule has sustained or same-sample corroboration.
- `candidate`: a threshold fired without enough causal support, or a historical peak recovered.
- `confirmed`: assign only during cross-module synthesis; the script intentionally does not emit it.

Do not turn a single threshold crossing into a root-cause statement. State what the evidence proves and what remains to verify.

## Modify collection

Read `references/collector-extension.md` completely before touching any OSWbb installation.

1. Require an explicit target host and OSWbb directory.
2. Inspect the live `OSWatcher.sh`, `OSWatcherFM.sh`, running command line, platform, version, archive path, and child scripts. Do not use a similarly named source checkout as the live baseline.
3. Back up affected files before editing.
4. To disable a built-in collector, stop OSWbb and reversibly disable its complete scheduling block. Do not comment only the `./xxxsub.sh` call because the parent may create a lock that no child removes.
5. To add a collector, implement the complete native pattern: child script, dependency discovery, archive directory, stale-lock cleanup, hourly header/compression, lock-protected scheduling, retention cleanup, and rollback.
6. Run shell syntax checks, restart with the exact original parameters, and verify at least two snapshot cycles. Confirm the target behavior and unchanged writes for unrelated modules.

Never stop, restart, or modify OSWbb during an analysis-only request.

## Validate the analyzer

Run:

```bash
python3 scripts/oswbb_analyze.py self-check
```

The script uses only Python 3 standard-library modules. Treat a failed self-check or a non-empty `errors` array as incomplete analysis.

## Rule provenance

Read `references/rule-provenance.md` when refreshing thresholds or behavior. Rules are a versioned snapshot, not a runtime dependency on the source repository.
