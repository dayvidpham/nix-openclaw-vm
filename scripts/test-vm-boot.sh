#!/usr/bin/env bash
# test-vm-boot.sh — Boot a test VM alongside the production one.
#
# Uses the test-vm-boot flake output which has a separate TAP interface
# (vm-oc-test), MAC address, and VSOCK CID (42) so the running
# openclaw-vm is not disturbed.
#
# Usage:  sudo ./scripts/test-vm-boot.sh
#
# Prerequisites: nix build .#test-vm-boot
# Press Ctrl+C or type 'poweroff' in the guest to stop.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
RESULT="${PROJECT_DIR}/result"

if [[ ! -x "$RESULT/bin/microvm-run" ]]; then
  echo "error: $RESULT/bin/microvm-run not found." >&2
  echo "Run 'nix build .#test-vm-boot' first." >&2
  exit 1
fi

RESULT="$(realpath "$RESULT")"
WORKDIR="$(mktemp -d /tmp/test-vm-boot.XXXXXX)"
echo "Working directory: $WORKDIR"

cleanup() {
  echo ""
  echo "=== Cleaning up ==="

  # Kill virtiofsd supervisor if still running
  if [[ -n "${VIRTIOFSD_PID:-}" ]] && kill -0 "$VIRTIOFSD_PID" 2>/dev/null; then
    echo "Stopping virtiofsd..."
    kill "$VIRTIOFSD_PID" 2>/dev/null || true
    wait "$VIRTIOFSD_PID" 2>/dev/null || true
  fi

  # Remove test tap interface (created by tap-up)
  if ip link show vm-oc-test &>/dev/null; then
    echo "Removing tap interface vm-oc-test..."
    ip link delete vm-oc-test 2>/dev/null || true
  fi

  rm -rf "$WORKDIR"
  echo "Done."
}
trap cleanup EXIT

# --- Create test tap interface ---
echo "=== Setting up TAP interface ==="
"$RESULT/bin/tap-up"

# --- Launch in temp directory ---
cd "$WORKDIR"

echo "=== Starting virtiofsd ==="
"$RESULT/bin/virtiofsd-run" &
VIRTIOFSD_PID=$!

# Wait for sockets to appear
for i in $(seq 1 30); do
  if [[ -S openclaw-vm-virtiofs-nix-store.sock && -S openclaw-vm-virtiofs-credproxy-state.sock ]]; then
    break
  fi
  sleep 0.5
done

if [[ ! -S openclaw-vm-virtiofs-nix-store.sock ]]; then
  echo "error: virtiofsd sockets did not appear after 15s" >&2
  exit 1
fi

echo "=== Launching test VM (CID=42, TAP=vm-oc-test, Ctrl+C to stop) ==="
echo ""
"$RESULT/bin/microvm-run" || true
