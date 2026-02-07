# Debug script for Tailscale and gateway services in openclaw-vm
{ pkgs }:

pkgs.writeShellScriptBin "debug-tailscale" ''
  set -euo pipefail

  OUTPUT_DIR="/tmp/openclaw-debug-$(date +%Y%m%d-%H%M%S)"
  mkdir -p "$OUTPUT_DIR"

  echo "Collecting diagnostics to $OUTPUT_DIR..."

  # Services to check
  SERVICES=(
      "tailscaled"
      "tailscaled-autoconnect"
      "tailscale-serve"
      "openclaw-gateway"
      "vsock-gateway-proxy"
  )

  # Collect systemctl status for each service
  echo "=== Collecting systemctl status ==="
  for svc in "''${SERVICES[@]}"; do
      echo "  - $svc"
      systemctl status "$svc" --no-pager 2>&1 > "$OUTPUT_DIR/''${svc}.status" || true
  done

  # Collect journalctl logs for each service
  echo "=== Collecting journal logs ==="
  for svc in "''${SERVICES[@]}"; do
      echo "  - $svc"
      journalctl -u "$svc" --no-pager -n 200 2>&1 > "$OUTPUT_DIR/''${svc}.log" || true
  done

  # Tailscale-specific diagnostics
  echo "=== Collecting Tailscale diagnostics ==="
  {
      echo "=== tailscale status ==="
      ${pkgs.tailscale}/bin/tailscale status 2>&1 || echo "tailscale status failed"

      echo ""
      echo "=== tailscale debug prefs ==="
      ${pkgs.tailscale}/bin/tailscale debug prefs 2>&1 || echo "tailscale debug prefs failed"

      echo ""
      echo "=== tailscale serve status ==="
      ${pkgs.tailscale}/bin/tailscale serve status 2>&1 || echo "tailscale serve status failed"
  } > "$OUTPUT_DIR/tailscale-diag.txt"

  # Check credential files
  echo "=== Checking credentials ==="
  {
      echo "=== /run/credentials (if accessible) ==="
      ls -la /run/credentials/ 2>&1 || echo "Cannot list /run/credentials"

      echo ""
      echo "=== tailscaled credentials ==="
      ls -la /run/credentials/tailscaled.service/ 2>&1 || echo "Cannot list tailscaled credentials"

      echo ""
      echo "=== Tailscale state directory ==="
      ls -la /var/lib/openclaw/tailscale/ 2>&1 || echo "Cannot list tailscale state dir"
  } > "$OUTPUT_DIR/credentials.txt"

  # Network info
  echo "=== Collecting network info ==="
  {
      echo "=== ip addr ==="
      ${pkgs.iproute2}/bin/ip addr

      echo ""
      echo "=== ip route ==="
      ${pkgs.iproute2}/bin/ip route

      echo ""
      echo "=== firewall interfaces ==="
      cat /proc/net/dev

      echo ""
      echo "=== listening ports ==="
      ${pkgs.iproute2}/bin/ss -tlnp 2>/dev/null || echo "Cannot list ports"
  } > "$OUTPUT_DIR/network.txt"

  # Create summary
  echo "=== Creating summary ==="
  {
      echo "=== Service Status Summary ==="
      for svc in "''${SERVICES[@]}"; do
          status=$(systemctl is-active "$svc" 2>/dev/null || echo "unknown")
          printf "%-25s %s\n" "$svc:" "$status"
      done

      echo ""
      echo "=== Tailscale Connection ==="
      ${pkgs.tailscale}/bin/tailscale status --json 2>/dev/null | head -20 || echo "Cannot get tailscale status"
  } > "$OUTPUT_DIR/summary.txt"

  # Create tarball
  TARBALL="/tmp/openclaw-debug-$(date +%Y%m%d-%H%M%S).tar.gz"
  tar -czf "$TARBALL" -C "$(dirname "$OUTPUT_DIR")" "$(basename "$OUTPUT_DIR")"

  echo ""
  echo "=== Done ==="
  echo "Diagnostics saved to: $OUTPUT_DIR"
  echo "Tarball created: $TARBALL"
  echo ""
  echo "To view summary: cat $OUTPUT_DIR/summary.txt"
''
