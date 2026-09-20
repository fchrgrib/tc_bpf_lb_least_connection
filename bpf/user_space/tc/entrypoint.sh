#!/bin/sh
# Auto-detect host iface, then run the TC least-connection loader.
# All flexible via DaemonSet env — no rebuild needed to switch service/port:
#   LB_IFACE        - e.g. eth0 / enp1s0 / ens3. Empty = auto-detect.
#   LB_NODEPORT     - must match your Service's nodePort (any 1-65535, e.g. 30080).
#   LB_BE1 / LB_BE2 - optional static fallback backends ("auto" = dynamic-only,
#                     live IPs come from /sys/fs/bpf/service_pod_ips via tracker).
#   LB_TARGET_PORT  - must match backend containerPort / Service targetPort.
set -eu

IFACE="${LB_IFACE:-}"
NODEPORT="${LB_NODEPORT:-30080}"
BE1="${LB_BE1:-auto}"
BE2="${LB_BE2:-auto}"
TARGET_PORT="${LB_TARGET_PORT:-8000}"

if [ -z "$IFACE" ]; then
  # hostNetwork=true, so this sees host routes.
  IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1)
  if [ -z "$IFACE" ]; then
    IFACE=$(ls /sys/class/net | grep -v '^lo$' | head -n1)
  fi
fi

echo "[tc-loader] iface=$IFACE nodeport=$NODEPORT be1=$BE1 be2=$BE2 targetPort=$TARGET_PORT"
exec /app/tc-loader "$IFACE" "$NODEPORT" "$BE1" "$BE2" "$TARGET_PORT"
