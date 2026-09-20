#!/bin/bash
# Stop + remove the TC eBPF LB installed by kube/build-and-install.sh.
#
# Base LB only (tracker + tc-loader):
#   ./kube/uninstall.sh
#
# Everything (base LB + active-conn + map_sync):
#   ./kube/uninstall.sh --all
#
# A single component:
#   ONLY=active-conn ./kube/uninstall.sh
#   ONLY=map-sync    ./kube/uninstall.sh
#
# Custom namespace:
#   NAMESPACE=prod ./kube/uninstall.sh --all
#
# Also purge host-side state (pinned eBPF maps) on every node:
#   PURGE=1 ./kube/uninstall.sh --all
#
# Deleting the DaemonSets sends SIGTERM: tc-loader detaches the TC program and
# the preStop hook removes the clsact qdisc, so the NodePort traffic falls back
# to kube-proxy immediately. Reinstall any time with build-and-install.sh.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

NS="${NAMESPACE:-default}"

ALL="${ALL:-0}"
for arg in "$@"; do
  case "$arg" in
    --all) ALL=1 ;;
  esac
done
ONLY="${ONLY:-all}"

# ── Decide what to remove (mirrors build-and-install.sh) ────────────────────
if [ "$ALL" = "1" ]; then
  RM_BASE=1; RM_ACTIVE=1; RM_MAPSYNC=1
else
  case "$ONLY" in
    active-conn) RM_BASE=0; RM_ACTIVE=1; RM_MAPSYNC=0 ;;
    map-sync)    RM_BASE=0; RM_ACTIVE=0; RM_MAPSYNC=1 ;;
    *)           RM_BASE=1; RM_ACTIVE=0; RM_MAPSYNC=0 ;;
  esac
fi

del() { kubectl delete --ignore-not-found=true --wait=true "$@"; }

# Best-effort host cleanup while the pods still exist. The pinned maps live on
# each node's /sys/fs/bpf; only a pod with that mount can remove them.
purge_maps() {
  [ "${PURGE:-0}" = "1" ] || return 0
  local pods pod c
  pods=$(kubectl -n "$NS" get pods -l app=pod-ip-tracker -o name 2>/dev/null || true)
  if [ -z "$pods" ]; then
    echo "    no tracker pods to exec into; skipping map purge"
    return 0
  fi
  for pod in $pods; do
    for c in tracker tc-loader; do
      if kubectl -n "$NS" exec "$pod" -c "$c" -- \
           sh -c 'rm -f /sys/fs/bpf/service_pod_ips /sys/fs/bpf/selected /sys/fs/bpf/hash_map' \
           2>/dev/null; then
        echo "    purged pinned maps via ${pod#pod/}/$c"
      fi
    done
  done
}

# ── Stop + remove ───────────────────────────────────────────────────────────
if [ "$RM_BASE" = "1" ]; then
  echo "==> Stopping base LB (DaemonSet/pod-ip-tracker, namespace=$NS)"
  purge_maps
  del -n "$NS" -f "$ROOT/kube/service/pt_daemonset.yaml"
  del -n "$NS" -f <(sed "s|__NAMESPACE__|$NS|g" "$ROOT/kube/service/pt_rbac.yaml")
  # Clean up cluster-wide grants left by very old installs (best effort).
  del clusterrole/pod-ip-tracker clusterrolebinding/pod-ip-tracker
fi

if [ "$RM_ACTIVE" = "1" ]; then
  echo "==> Stopping active-conn (DaemonSet/active-conn)"
  del -n "$NS" -f "$ROOT/kube/active_conn/daemonset.yaml"
  del -n "$NS" -f "$ROOT/kube/active_conn/rbac.yaml"
fi

if [ "$RM_MAPSYNC" = "1" ]; then
  echo "==> Stopping map-sync (DaemonSet/map-sync)"
  del -n "$NS" -f "$ROOT/kube/map_sync/daemonset.yaml"
  del -n "$NS" -f "$ROOT/kube/map_sync/networkpolicy.yaml"
  del -n "$NS" -f "$ROOT/kube/map_sync/certificate.yaml"
  del -n "$NS" -f "$ROOT/kube/map_sync/service.yaml"
  del -n "$NS" -f "$ROOT/kube/map_sync/rbac.yaml"
  # map-sync's own CA + ClusterIssuer (cluster-scoped; safe to remove).
  del -f "$ROOT/kube/map_sync/cert-manager.yaml"
fi

echo
echo "OK. Load balancer stopped."
echo "  NodePort traffic now falls back to kube-proxy."
echo "  Restart with: ./kube/build-and-install.sh --all"
if [ "${PURGE:-0}" != "1" ]; then
  echo "  Pinned eBPF maps: left on nodes (harmless; use PURGE=1 to remove)."
fi
