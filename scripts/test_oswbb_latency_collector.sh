#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' 0 1 2 15

mkdir -p "$tmp/bin" "$tmp/locks"
cat > "$tmp/bin/ping" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$PING_CALLS"
case " $* " in
  *" 10.0.0.99 "*)
    echo 'ping: invalid target' >&2
    exit 2
    ;;
esac
case " $* " in
  *" -s 56 "*)
    echo '64 bytes from 10.0.0.12: icmp_seq=1 ttl=64 time=0.183 ms'
    exit 0
    ;;
  *" -s 8192 "*)
    exit 1
    ;;
esac
exit 2
EOF
chmod +x "$tmp/bin/ping"

printf 'node2 10.0.0.12\nnode3 10.0.0.13\n' > "$tmp/oswlatency.conf"
touch "$tmp/locks/latencylock.file"

PING_CALLS="$tmp/calls" \
PATH="$tmp/bin:$PATH" \
OSWBB_LATENCY_CONF="$tmp/oswlatency.conf" \
OSWBB_LATENCY_LOCK="$tmp/locks/latencylock.file" \
OSWBB_LATENCY_SOURCE=node1 \
sh "$root/release/oswbb-latency/latencysub.sh" "$tmp/output"

test "$(grep -c -- '-s 56' "$tmp/calls")" -eq 2
test "$(grep -c -- '-s 8192' "$tmp/calls")" -eq 2
test "$(grep -c 'size=56|status=ok|rtt_ms=0.183$' "$tmp/output")" -eq 2
test "$(grep -c 'size=8192|status=timeout|rtt_ms=$' "$tmp/output")" -eq 2
test ! -e "$tmp/locks/latencylock.file"

touch "$tmp/locks/latencylock.file"
OSWBB_LATENCY_CONF="$tmp/missing.conf" \
OSWBB_LATENCY_LOCK="$tmp/locks/latencylock.file" \
OSWBB_LATENCY_SOURCE=node1 \
sh "$root/release/oswbb-latency/latencysub.sh" "$tmp/missing-output"
grep -q 'size=0|status=config_error|rtt_ms=$' "$tmp/missing-output"
test ! -e "$tmp/locks/latencylock.file"

printf 'bad-entry\n# comment\n' > "$tmp/malformed.conf"
touch "$tmp/locks/latencylock.file"
PING_CALLS="$tmp/malformed-calls" \
PATH="$tmp/bin:$PATH" \
OSWBB_LATENCY_CONF="$tmp/malformed.conf" \
OSWBB_LATENCY_LOCK="$tmp/locks/latencylock.file" \
OSWBB_LATENCY_SOURCE=node1 \
sh "$root/release/oswbb-latency/latencysub.sh" "$tmp/malformed-output"
grep -q 'target=bad-entry|address=|size=0|status=config_error|rtt_ms=$' "$tmp/malformed-output"
test ! -s "$tmp/malformed-calls"
test ! -e "$tmp/locks/latencylock.file"

printf 'node9 10.0.0.99\n' > "$tmp/ping-error.conf"
touch "$tmp/locks/latencylock.file"
PING_CALLS="$tmp/ping-error-calls" \
PATH="$tmp/bin:$PATH" \
OSWBB_LATENCY_CONF="$tmp/ping-error.conf" \
OSWBB_LATENCY_LOCK="$tmp/locks/latencylock.file" \
OSWBB_LATENCY_SOURCE=node1 \
sh "$root/release/oswbb-latency/latencysub.sh" "$tmp/ping-error-output"
test "$(grep -c 'status=ping_error|rtt_ms=$' "$tmp/ping-error-output")" -eq 2
test ! -e "$tmp/locks/latencylock.file"

patch_file="$root/release/oswbb-latency/OSWatcher-latency.patch"
example_conf="$root/release/oswbb-latency/oswlatency.conf.example"
test -f "$patch_file"
test -f "$example_conf"

mkdir -p "$tmp/oswbb"
cp "$root/other/oswbb-upstream/OSWatcher.sh" "$tmp/oswbb/OSWatcher.sh"
cp "$root/other/oswbb-upstream/OSWatcherFM.sh" "$tmp/oswbb/OSWatcherFM.sh"
patch -s -p1 -d "$tmp/oswbb" < "$patch_file"
sh -n "$tmp/oswbb/OSWatcher.sh" "$tmp/oswbb/OSWatcherFM.sh"
grep -q 'latencysub.sh' "$tmp/oswbb/OSWatcher.sh"
grep -q 'oswlatency' "$tmp/oswbb/OSWatcherFM.sh"
test "$(grep -cv '^[[:space:]]*#\|^[[:space:]]*$' "$example_conf")" -eq 2
