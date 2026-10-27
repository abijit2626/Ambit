#!/usr/bin/env bash
set -euo pipefail

BIN_PATH=/usr/local/bin/ambitd

case "$(uname -s)" in
  Linux) CONFIG=/etc/ambit/config.json ;;
  Darwin) CONFIG=/usr/local/etc/ambit/config.json ;;
  *)
    echo "unsupported OS $(uname -s); on Windows use scripts/verify-restart.ps1" >&2
    exit 1
    ;;
esac

die() { echo "verify-restart: $*" >&2; exit 1; }
say() { echo "verify-restart: $*"; }

usage() {
  cat >&2<<'USAGE'
Kill ambitd and time how long the service manager takes to bring it back. This is the check
the cohort checklist asks for before a rollout (blocker 2): systemd Restart=always and
launchd KeepAlive are in the service definitions, and neither has been observed to fire.

  sudo ./scripts/verify-restart.sh                  # kill once, wait up to 120 s
  sudo ./scripts/verify-restart.sh --timeout 30     # fail if it takes longer than 30 s
  sudo ./scripts/verify-restart.sh --url http://127.0.0.1:7777

It sends SIGKILL, so the process gets no chance to write a final heartbeat: the next run
reports the stop as unclean, which is the point. Run it on a test machine, not on a
volunteer's.

Passes when a different ambitd process is running and its health endpoint answers. A process
that comes back is not enough, because a daemon that starts and cannot serve is still
unobserved. Exit status 0 on a pass, 1 on a failure, 2 on a usage error.

Windows: scripts/verify-restart.ps1.
USAGE
  exit 2
}

url="" timeout=120
while [ $# -gt 0 ]; do
  case "$1" in
    --timeout) [ $# -ge 2 ] || usage; timeout="$2"; shift 2 ;;
    --url) [ $# -ge 2 ] || usage; url="$2"; shift 2 ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done
case "$timeout" in ''|*[!0-9]*) echo "--timeout takes whole seconds, got '$timeout'" >&2; usage ;; esac
[ "$timeout" -gt 0 ] || { echo "--timeout must be greater than zero" >&2; usage; }

if [ -z "$url" ]; then
  addr=""
  if [ -x "$BIN_PATH" ]; then
    addr=$("$BIN_PATH" -config "$CONFIG" -print-config 2>/dev/null \
      | sed -n 's/^ *"hook_addr": *"\([^"]*\)".*/\1/p' | head -1) || true
  fi
  url="http://${addr:-127.0.0.1:7777}"
fi

healthy() { curl -fsS --max-time 2 "$url/healthz" >/dev/null 2>&1; }

# pgrep counts a killed process until its parent reaps it, which would read as a second ambitd.
live_pids() {
  local p st
  for p in $(pgrep -x ambitd || true); do
    st=$(ps -o stat= -p "$p" 2>/dev/null | tr -d ' ') || true
    case "$st" in ''|Z*) ;; *) echo "$p" ;; esac
  done
}

pids=$(live_pids)
[ -n "$pids" ] || die "no ambitd process is running"
[ "$(echo "$pids" | wc -l)" -eq 1 ] || die "more than one ambitd is running ($(echo "$pids" | tr '\n' ' ')); stop the extra one first so the result means something"
old=$pids
healthy || die "ambitd (pid $old) is running but $url/healthz does not answer; fix that before testing a restart"

say "killing ambitd pid $old with SIGKILL"
start=$(date +%s)
kill -KILL "$old" 2>/dev/null || die "could not kill pid $old: run as root"

while :; do
  now=$(date +%s)
  elapsed=$((now - start))
  new=$(live_pids)
  if [ -n "$new" ] && [ "$new" != "$old" ] && [ "$(echo "$new" | wc -l)" -eq 1 ] && healthy; then
    say "PASS: back as pid $new, health endpoint answering, after ${elapsed}s"
    exit 0
  fi
  if [ "$elapsed" -ge "$timeout" ]; then
    if [ -n "$new" ] && [ "$new" != "$old" ]; then
      die "FAIL: a new ambitd (pid $new) is running but $url/healthz did not answer within ${timeout}s"
    fi
    die "FAIL: ambitd did not come back within ${timeout}s; the service manager did not restart it"
  fi
  sleep 0.5
done
