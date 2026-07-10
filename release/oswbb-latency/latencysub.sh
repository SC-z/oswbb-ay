#!/bin/sh

if [ "$#" -ne 1 ]; then
  echo "usage: $0 OUTPUT_FILE" >&2
  exit 2
fi

output=$1
conf=${OSWBB_LATENCY_CONF:-oswlatency.conf}
lock=${OSWBB_LATENCY_LOCK:-locks/latencylock.file}
source_host=${OSWBB_LATENCY_SOURCE:-`hostname`}

cleanup() {
  rm -f "$lock"
}

trap cleanup 0
trap 'exit 1' 1 2 15

now() {
  date '+%Y-%m-%dT%H:%M:%S%z'
}

record() {
  printf 'OSWLATENCY|timestamp=%s|source=%s|target=%s|address=%s|size=%s|status=%s|rtt_ms=%s\n' \
    "$1" "$source_host" "$2" "$3" "$4" "$5" "$6" >> "$output"
}

echo "zzz ***`date '+%a %b %e %T %Z %Y'`" >> "$output"

if [ ! -r "$conf" ]; then
  record "`now`" "" "" 0 config_error ""
  exit 0
fi

valid=0
config_errors=0
while read -r target address extra; do
  case "$target" in
    ''|'#'*) continue ;;
  esac

  invalid=0
  [ -n "$address" ] && [ -z "$extra" ] || invalid=1
  case "$target" in *[!A-Za-z0-9._-]*) invalid=1 ;; esac
  case "$address" in ''|*[!0-9.]*) invalid=1 ;; esac
  if [ "$invalid" -eq 1 ]; then
    record "`now`" "$target" "$address" 0 config_error ""
    config_errors=1
    continue
  fi

  valid=1
  for size in 56 8192; do
    timestamp=`now`
    raw=`ping -n -c 1 -W 1 -s "$size" "$address" 2>&1`
    rc=$?
    printf '%s\n' "$raw" >> "$output"
    rtt=`printf '%s\n' "$raw" | awk '{for (i=1;i<=NF;i++) if ($i ~ /^time[=<]/) {sub(/^time[=<]/,"",$i); print $i; exit}}'`

    if [ "$rc" -eq 0 ] && [ -n "$rtt" ]; then
      status=ok
    elif [ "$rc" -eq 1 ]; then
      status=timeout
      rtt=
    else
      status=ping_error
      rtt=
    fi
    record "$timestamp" "$target" "$address" "$size" "$status" "$rtt"
  done
done < "$conf"

if [ "$valid" -eq 0 ] && [ "$config_errors" -eq 0 ]; then
  record "`now`" "" "" 0 config_error ""
fi
