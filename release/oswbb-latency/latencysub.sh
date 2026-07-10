#!/bin/sh

if [ "$#" -ne 1 ]; then
  echo "usage: $0 OUTPUT_FILE" >&2
  exit 2
fi

output=$1
conf=${OSWBB_LATENCY_CONF:-oswlatency.conf}
lock=${OSWBB_LATENCY_LOCK:-locks/latencylock.file}

cleanup() {
  rm -f "$lock"
}

trap cleanup 0
trap 'exit 1' 1 2 15

echo "zzz ***`date '+%a %b %e %T %Z %Y'`" >> "$output"

if [ ! -r "$conf" ]; then
  echo "zzz ***OSWLATENCY config error: cannot read $conf" >> "$output"
  exit 0
fi

valid=0
while read -r target address extra; do
  case "$target" in
    ''|'#'*) continue ;;
  esac

  invalid=0
  [ -n "$address" ] && [ -z "$extra" ] || invalid=1
  case "$target" in *[!A-Za-z0-9._-]*) invalid=1 ;; esac
  case "$address" in ''|*[!0-9.]*) invalid=1 ;; esac
  if [ "$invalid" -eq 1 ]; then
    echo "zzz ***OSWLATENCY config error: invalid target line: $target $address" >> "$output"
    continue
  fi

  valid=1
  for size in 56 8192; do
    echo "zzz ***OSWLATENCY target=$target address=$address size=$size" >> "$output"
    ping -n -c 1 -W 1 -s "$size" "$address" >> "$output" 2>&1
  done
done < "$conf"

if [ "$valid" -eq 0 ]; then
  echo "zzz ***OSWLATENCY config error: no valid targets" >> "$output"
fi
