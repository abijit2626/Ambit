#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

BIN_PATH=/usr/local/bin/ambitd
BUNDLE="$ROOT/deploy/claude-code/managed-settings.m0.json"

EARLIER_BUNDLES="44fccfc3cec5e1b35c32c51d7a676ca9214eb15b3fe3099cd5298f2a28a56ed5 75c7221167965f343ae3208ed3deae20dda1bdccef28ee39fc096e871ba22d7c"

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
  cat >&2<<'USAGE'
Install ambitd as a system service on Linux (systemd) or macOS (launchd), the way a
monitoring agent like Sysmon runs: as root, from boot, with the service manager set to restart
it (systemd Restart=always, launchd KeepAlive; neither restart has been observed yet).

  sudo ./scripts/install-system.sh --binary bin/ambitd-linux-amd64   # install and start
  sudo ./scripts/install-system.sh --status                          # is it running?
  sudo ./scripts/install-system.sh --uninstall                       # remove; keep data
  sudo ./scripts/install-system.sh --uninstall --purge               # remove data too

What install does, in this order:
  1. copies the binary to /usr/local/bin/ambitd and installs the service definition
     from deploy/service/;
  2. starts the service and waits for its health endpoint;
  3. only then installs the observation-only managed-settings bundle, so Claude Code
     is never pointed at a daemon that is not there.

It refuses to replace managed settings that already exist and differ from the bundle:
an organization's own policy may be in that file, and overwriting it would silently
drop that policy. Merge the bundle's "env" and "hooks" blocks into it by hand instead.
The one exception is the earlier bundle this installer shipped (SessionStart over http,
which Claude Code does not deliver): a file with exactly that content is upgraded.

Uninstall reverses the order: managed settings first, then the service. The spool and
the fingerprint key stay unless --purge is given, because they are the evidence a
later investigation may need.

Windows: scripts/install-system.ps1.
USAGE
  exit 2
}

require_root() {
  [ "$(id -u)" -eq 0 ] || die "run as root (sudo): the service, the binary and managed settings live in system paths"
}

PROBE_BIN=$BIN_PATH

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

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

is_earlier_bundle() {
  local h
  h=$(sha256_of "$1")
  case " $EARLIER_BUNDLES " in *" $h "*) return 0 ;; *) return 1 ;; esac
}

bundle_problem() {
  local want="\"command\": \"$BIN_PATH hook-forward\""
  if ! grep -qF "$want" "$BUNDLE"; then
    echo "the bundle does not run $BIN_PATH hook-forward for SessionStart (it looks for: $want), so SessionStart would go missing"
  fi
}

install_managed_settings() {
  if [ -f "$MANAGED" ]; then
    if cmp -s "$BUNDLE" "$MANAGED"; then
      say "managed settings already match the M0 bundle: $MANAGED"
      return 0
    fi
    if is_earlier_bundle "$MANAGED"; then
      install -m 0644 "$BUNDLE" "$MANAGED.new"
      mv -f "$MANAGED.new" "$MANAGED"
      say "upgraded managed settings from the earlier ambit bundle (SessionStart over http, which Claude Code does not deliver): $MANAGED"
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
    if cmp -s "$BUNDLE" "$MANAGED" || is_earlier_bundle "$MANAGED"; then
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
  local problem
  problem=$(bundle_problem)
  [ -z "$problem" ] || die "$problem"
  local ver
  ver=$("$bin" -version 2>/dev/null) || die "$bin does not run here: wrong OS or CPU architecture?"
  PROBE_BIN=$bin

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
  say "done. Data: $DATA_DIR. Start a Claude Code session and send one prompt: $DATA_DIR/events.jsonl
  should gain a session_start line and a prompt_submit line."
  say "session_start arrives through the hook-forward command hook (README, Known limitations); if only prompt_submit appears, run the hook command from the managed settings by hand."
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
    if cmp -s "$BUNDLE" "$MANAGED"; then echo "managed settings: the M0 bundle ($MANAGED)"
    elif is_earlier_bundle "$MANAGED"; then echo "managed settings: an earlier ambit bundle whose SessionStart hook is not delivered; run the installer again to upgrade ($MANAGED)"
    else echo "managed settings: present, not the M0 bundle ($MANAGED)"; fi
  else
    echo "managed settings: absent"
  fi
  echo "data:             $DATA_DIR"
  if [ -x "$BIN_PATH" ] && [ -f "$DATA_DIR/trajectory.jsonl" ]; then
    echo
    "$BIN_PATH" report -config "$CONFIG" || echo "ambitd report failed" >&2
  fi
  if [ -x "$BIN_PATH" ]; then
    echo
    echo "(doctor runs as $(id -un) here; run 'ambitd doctor' as each developer to read their own settings too)"
    "$BIN_PATH" doctor -config "$CONFIG" || echo "ambitd doctor found a problem (above)" >&2
  fi
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
