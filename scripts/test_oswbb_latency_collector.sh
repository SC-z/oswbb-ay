#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' 0 1 2 15

mkdir -p "$tmp/bin" "$tmp/locks"
cat > "$tmp/bin/ping" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >> "$PING_CALLS"
address=
for arg do
  address=$arg
done
case " $* " in
  *" 10.0.0.99 "*)
    echo 'ping: invalid target' >&2
    exit 2
    ;;
esac
case " $* " in
  *" -s 56 "*)
    echo "PING $address ($address) 56(84) bytes of data."
    echo "64 bytes from $address: icmp_seq=1 ttl=64 time=0.183 ms"
    echo '1 packets transmitted, 1 received, 0% packet loss'
    exit 0
    ;;
  *" -s 8192 "*)
    echo "PING $address ($address) 8192(8220) bytes of data."
    echo '1 packets transmitted, 0 received, 100% packet loss'
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
sh "$root/release/oswbb-latency/latencysub.sh" "$tmp/output"

test "$(grep -c -- '-s 56' "$tmp/calls")" -eq 2
test "$(grep -c -- '-s 8192' "$tmp/calls")" -eq 2
test "$(grep -c 'OSWLATENCY target=.* size=56$' "$tmp/output")" -eq 2
test "$(grep -c 'OSWLATENCY target=.* size=8192$' "$tmp/output")" -eq 2
grep -q '64 bytes from 10.0.0.12: icmp_seq=1 ttl=64 time=0.183 ms' "$tmp/output"
grep -q '1 packets transmitted, 0 received, 100% packet loss' "$tmp/output"
! grep -q 'status=' "$tmp/output"
! grep -q 'rtt_ms=' "$tmp/output"
test ! -e "$tmp/locks/latencylock.file"

touch "$tmp/locks/latencylock.file"
OSWBB_LATENCY_CONF="$tmp/missing.conf" \
OSWBB_LATENCY_LOCK="$tmp/locks/latencylock.file" \
sh "$root/release/oswbb-latency/latencysub.sh" "$tmp/missing-output"
grep -q 'OSWLATENCY config error: cannot read ' "$tmp/missing-output"
test ! -e "$tmp/locks/latencylock.file"

printf 'bad-entry\n# comment\n' > "$tmp/malformed.conf"
touch "$tmp/locks/latencylock.file"
PING_CALLS="$tmp/malformed-calls" \
PATH="$tmp/bin:$PATH" \
OSWBB_LATENCY_CONF="$tmp/malformed.conf" \
OSWBB_LATENCY_LOCK="$tmp/locks/latencylock.file" \
sh "$root/release/oswbb-latency/latencysub.sh" "$tmp/malformed-output"
grep -q 'OSWLATENCY config error: invalid target line: bad-entry' "$tmp/malformed-output"
test ! -s "$tmp/malformed-calls"
test ! -e "$tmp/locks/latencylock.file"

printf 'node9 10.0.0.99\n' > "$tmp/ping-error.conf"
touch "$tmp/locks/latencylock.file"
PING_CALLS="$tmp/ping-error-calls" \
PATH="$tmp/bin:$PATH" \
OSWBB_LATENCY_CONF="$tmp/ping-error.conf" \
OSWBB_LATENCY_LOCK="$tmp/locks/latencylock.file" \
sh "$root/release/oswbb-latency/latencysub.sh" "$tmp/ping-error-output"
test "$(grep -c 'OSWLATENCY target=node9 address=10.0.0.99 size=' "$tmp/ping-error-output")" -eq 2
test "$(grep -c 'ping: invalid target' "$tmp/ping-error-output")" -eq 2
! grep -q 'status=' "$tmp/ping-error-output"
test ! -e "$tmp/locks/latencylock.file"

mkdir -p "$tmp/three-node"
printf 'node2 10.0.0.12\nnode3 10.0.0.13\n' > "$tmp/three-node/node1.conf"
printf 'node1 10.0.0.11\nnode3 10.0.0.13\n' > "$tmp/three-node/node2.conf"
printf 'node1 10.0.0.11\nnode2 10.0.0.12\n' > "$tmp/three-node/node3.conf"

for cycle in 1 2 3; do
  for source in node1 node2 node3; do
    touch "$tmp/three-node/$source.lock"
    PING_CALLS="$tmp/three-node/calls" \
    PATH="$tmp/bin:$PATH" \
    OSWBB_LATENCY_CONF="$tmp/three-node/$source.conf" \
    OSWBB_LATENCY_LOCK="$tmp/three-node/$source.lock" \
    sh "$root/release/oswbb-latency/latencysub.sh" "$tmp/three-node/$source.out"
    test ! -e "$tmp/three-node/$source.lock"
  done
done

test "$(grep -c -- '-s 56' "$tmp/three-node/calls")" -eq 18
test "$(grep -c -- '-s 8192' "$tmp/three-node/calls")" -eq 18
for source in node1 node2 node3; do
  case "$source" in
    node1) targets='node2 node3' ;;
    node2) targets='node1 node3' ;;
    node3) targets='node1 node2' ;;
  esac
  for target in $targets; do
    for size in 56 8192; do
      test "$(grep -c "OSWLATENCY target=$target address=.* size=$size$" "$tmp/three-node/$source.out")" -eq 3
    done
  done
  ! grep -q 'status=\|rtt_ms=' "$tmp/three-node/$source.out"
done

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
