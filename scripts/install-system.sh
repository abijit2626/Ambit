#!/usr/bin/env bash
# Install ambitd as a system service on Linux (systemd) or macOS (launchd), the way a
# monitoring agent like Sysmon runs: as root, from boot, restarted whenever it exits.
#
#   sudo ./scripts/install-system.sh --binary bin/ambitd-linux-amd64   # install and start
#   sudo ./scripts/install-system.sh --status                          # is it running?
#   sudo ./scripts/install-system.sh --uninstall                       # remove; keep data
#   sudo ./scripts/install-system.sh --uninstall --purge               # remove data too
#
# What install does, in this order:
#   1. copies the binary to /usr/local/bin/ambitd and installs the service definition
#      from deploy/service/;
#   2. starts the service and waits for its health endpoint;
#   3. only then installs the observation-only managed-settings bundle, so Claude Code
#      is never pointed at a daemon that is not there.
#
# It refuses to replace managed settings that already exist and differ from the bundle:
# an organization's own policy may be in that file, and overwriting it would silently
# drop that policy. Merge the bundle's "env" and "hooks" blocks into it by hand instead.
#
# Uninstall reverses the order: managed settings first, then the service. The spool and
# the fingerprint key stay unless --purge is given, because they are the evidence a
# later investigation may need.
#
# Windows: scripts/install-system.ps1.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

BIN_PATH=/usr/local/bin/ambitd
BUNDLE="$ROOT/deploy/claude-code/managed-settings.m0.json"

case "$(uname -s)" in
  Linux)
    OS=linux
    UNIT_SRC="$ROOT/deploy/service/ambitd.service"
    UNIT_DST=/etc/systemd/system/ambitd.service
    CONFIG=/etc/ambit/config.json
    DATA_DIR=/var/lib/ambit
    MANAGED=/etc/claude-code/managed-settings.json
    ;;
  Darwin)
    OS=macos
    LABEL=com.ambit.ambitd
    UNIT_SRC="$ROOT/deploy/service/$LABEL.plist"
    UNIT_DST=/Library/LaunchDaemons/$LABEL.plist
    CONFIG=/usr/local/etc/ambit/config.json
    DATA_DIR=/usr/local/var/ambit
    LOG_DIR=/Library/Logs/ambit
    MANAGED="/Library/Application Support/ClaudeCode/managed-settings.json"
    ;;
  *)
    echo "unsupported OS $(uname -s); on Windows use scripts/install-system.ps1" >&2
    exit 1
    ;;
esac

die() { echo "install-system: $*" >&2; exit 1; }
say() { echo "install-system: $*"; }

usage() {
  sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
  exit 2
}

require_root() {
  [ "$(id -u)" -eq 0 ] || die "run as root (sudo): the service, the binary and managed settings live in system paths"
}

# PROBE_BIN is the binary whose effective configuration says where ambitd listens: the
# one being installed during an install (nothing is at BIN_PATH yet on a first install),
# the installed one otherwise.
PROBE_BIN=$BIN_PATH

# hook_url is where ambitd listens, read from its effective configuration so a config
# that moves hook_addr is honored. It falls back to the default.
hook_url() {
  local addr=""
  if [ -x "$PROBE_BIN" ]; then
    addr=$("$PROBE_BIN" -config "$CONFIG" -print-config 2>/dev/null \
      | sed -n 's/^ *"hook_addr": *"\([^"]*\)".*/\1/p' | head -1) || true
  fi
  echo "http://${addr:-127.0.0.1:7777}"
}

healthy() {
  curl -fsS --max-time 2 "$(hook_url)/healthz" >/dev/null 2>&1
}

running() {
  case "$(service_state)" in active|loaded) return 0 ;; *) return 1 ;; esac
}

# wait_healthy needs the service itself running AND the endpoint answering. The endpoint
# alone is not proof: another process holding the port answers just as well, while the
# service fails to bind.
wait_healthy() {
  local i
  for i in $(seq 1 20); do
    if running && healthy; then return 0; fi
    sleep 0.5
  done
  return 1
}

service_start() {
  if [ "$OS" = linux ]; then
    install -m 0644 "$UNIT_SRC" "$UNIT_DST"
    systemctl daemon-reload
    systemctl enable ambitd >/dev/null
    systemctl restart ambitd
  else
    install -d -m 0700 "$LOG_DIR"
    install -m 0644 -o root -g wheel "$UNIT_SRC" "$UNIT_DST"
    launchctl bootout "system/$LABEL" 2>/dev/null || true
    # enable first: a label someone disabled stays disabled across bootstrap.
    launchctl enable "system/$LABEL"
    launchctl bootstrap system "$UNIT_DST"
  fi
}

service_stop() {
  if [ "$OS" = linux ]; then
    if [ -f "$UNIT_DST" ]; then
      systemctl disable --now ambitd >/dev/null 2>&1 || true
      rm -f "$UNIT_DST"
      systemctl daemon-reload
    fi
  else
    launchctl bootout "system/$LABEL" 2>/dev/null || true
    rm -f "$UNIT_DST"
  fi
}

service_state() {
  if [ "$OS" = linux ]; then
    local st
    st=$(systemctl is-active ambitd 2>/dev/null) || true
    echo "${st:-unknown}"
  else
    if launchctl print "system/$LABEL" >/dev/null 2>&1; then echo loaded; else echo "not loaded"; fi
  fi
}

install_managed_settings() {
  if [ -f "$MANAGED" ]; then
    if cmp -s "$BUNDLE" "$MANAGED"; then
      say "managed settings already match the M0 bundle: $MANAGED"
      return 0
    fi
    die "managed settings already exist at $MANAGED and differ from the M0 bundle.
  They may carry your organization's own policy, so they were not replaced.
  ambitd is installed and running; merge the \"env\" and \"hooks\" blocks of
  $BUNDLE into that file by hand, then confirm a Claude Code session
  produces events."
  fi
  install -d -m 0755 "$(dirname "$MANAGED")"
  install -m 0644 "$BUNDLE" "$MANAGED"
  say "installed managed settings: $MANAGED"
}

remove_managed_settings() {
  if [ -f "$MANAGED" ]; then
    if cmp -s "$BUNDLE" "$MANAGED"; then
      rm -f "$MANAGED"
      say "removed managed settings: $MANAGED"
    else
      say "left $MANAGED in place: it differs from the M0 bundle, so it is not only ours.
  Remove the ambit \"hooks\" and OTEL \"env\" entries from it by hand."
    fi
  fi
}

do_install() {
  local bin="$1"
  require_root
  [ -n "$bin" ] || die "--binary is required: the ambitd built for this OS and CPU (make cross writes bin/ambitd-<os>-<arch>)"
  [ -f "$bin" ] || die "no such file: $bin"
  [ -f "$UNIT_SRC" ] || die "missing $UNIT_SRC; run this from a checkout of the repository"
  [ -f "$BUNDLE" ] || die "missing $BUNDLE"
  # Running -version proves the binary is for this OS and CPU before anything changes.
  local ver
  ver=$("$bin" -version 2>/dev/null) || die "$bin does not run here: wrong OS or CPU architecture?"
  PROBE_BIN=$bin

  # A user-scope ambitd (scripts/dev-local.sh) holds the same port, and the service
  # would fail to bind. Only fail if what answers is not already this service.
  if healthy && ! running; then
    die "something already answers on $(hook_url): probably a user-scope ambitd.
  Remove it first with ./scripts/dev-local.sh --uninstall"
  fi

  install -d -m 0755 "$(dirname "$BIN_PATH")"
  install -m 0755 "$bin" "$BIN_PATH"
  say "installed $BIN_PATH ($ver)"

  service_start
  if ! wait_healthy; then
    if [ "$OS" = linux ]; then
      die "the service did not come up on $(hook_url); see: journalctl -u ambitd -n 50"
    fi
    die "the service did not come up on $(hook_url); see: tail -50 $LOG_DIR/ambitd.log"
  fi
  say "service running, health endpoint answers on $(hook_url)"

  install_managed_settings
  say "done. Data: $DATA_DIR. Start a Claude Code session and check that
  $DATA_DIR/events.jsonl gains a session_start line."
}

do_uninstall() {
  local purge="$1"
  require_root
  remove_managed_settings
  service_stop
  rm -f "$BIN_PATH"
  say "service and binary removed"
  if [ "$purge" = 1 ]; then
    rm -rf "$DATA_DIR"
    [ "$OS" = macos ] && rm -rf "$LOG_DIR"
    say "removed $DATA_DIR"
  elif [ -d "$DATA_DIR" ]; then
    say "kept $DATA_DIR (spool, events, fingerprint key); --purge removes it"
  fi
}

do_status() {
  echo "service:          $(service_state)"
  if healthy; then echo "health endpoint:  answers on $(hook_url)"; else echo "health endpoint:  no answer on $(hook_url)"; fi
  if [ -x "$BIN_PATH" ]; then echo "binary:           $BIN_PATH ($("$BIN_PATH" -version 2>/dev/null || echo '?'))"; else echo "binary:           not installed"; fi
  if [ -f "$MANAGED" ]; then
    if cmp -s "$BUNDLE" "$MANAGED"; then echo "managed settings: the M0 bundle ($MANAGED)"; else echo "managed settings: present, not the M0 bundle ($MANAGED)"; fi
  else
    echo "managed settings: absent"
  fi
  echo "data:             $DATA_DIR"
}

mode=install bin="" purge=0
while [ $# -gt 0 ]; do
  case "$1" in
    --binary) [ $# -ge 2 ] || usage; bin="$2"; shift 2 ;;
    --uninstall) mode=uninstall; shift ;;
    --status) mode=status; shift ;;
    --purge) purge=1; shift ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done
[ "$purge" = 0 ] || [ "$mode" = uninstall ] || die "--purge only goes with --uninstall"

case "$mode" in
  install) do_install "$bin" ;;
  uninstall) do_uninstall "$purge" ;;
  status) do_status ;;
esac
