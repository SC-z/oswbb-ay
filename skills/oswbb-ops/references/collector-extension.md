# OSWbb collector control and extension

## Always inspect the live installation

Treat the user-specified host and OSWbb directory as authoritative. Read:

- `OSWatcher.sh`
- `OSWatcherFM.sh`
- `startOSWbb.sh` and `stopOSWbb.sh`
- the running `OSWatcher.sh` command line
- relevant child scripts and locks
- the actual archive directory

Do not assume an `extras.txt` file exists. A stock 7.3.3 tree may contain only `Example_extras.txt`; inactive example files are not the live collection contract.

## Disable a collection item

1. Record the original process arguments.
2. Stop OSWbb and confirm the main process ended.
3. Back up `OSWatcher.sh`.
4. Identify the complete module scheduling block inside the main loop.
5. Reversibly comment or guard the complete block:
   - hourly header creation;
   - previous-hour compression;
   - lock inspection and creation;
   - child-script invocation.
6. Do not comment only the child invocation; this can leave a parent-created lock behind.
7. Run `sh -n OSWatcher.sh`.
8. Restart with the exact original arguments.
9. Observe at least two snapshot cycles:
   - target archive stops updating;
   - unrelated archives continue;
   - no new spanning-interval warning or stale target lock appears.

`OSWatcherFM.sh` does not schedule collection. Leaving its old-file cleanup block in place is harmless when disabling a collector.

## Add a custom collection item

Implement the native lifecycle instead of an unrelated daemon:

1. Create a small child script that accepts the destination file as argument 1, writes a `zzz ***<timestamp>` marker, appends raw command output and stderr, and removes its lock on every exit path.
2. Add dependency/platform discovery in `OSWatcher.sh`.
3. Create the archive subdirectory.
4. Remove stale lock during startup.
5. Add one main-loop block with hourly header, compression, lock protection, overrun warning, and asynchronous child execution.
6. Add matching retention cleanup to `OSWatcherFM.sh`.
7. Preserve the original snapshot interval, archive retention, compression tool, and archive destination.
8. Provide a reverse patch or backup-based rollback.

## Validation

- Run syntax checks on all changed shell scripts.
- Use a temporary copy and fake command to test success, timeout/error continuation, raw output, lock cleanup, hour naming, and retention.
- On a live host, deploy one node at a time and validate visible archive writes before proceeding.
- Never run a new high-load collector merely to test it without explicit authorization.
