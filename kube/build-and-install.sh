#!/bin/bash
# Build + install the TC eBPF LB from the control-plane.
# Run once on control-plane. After that, new nodes get the LB automatically
# via the DaemonSet, and removed nodes are cleaned up automatically.
#
# Flexible: pick any Service + NodePort without rebuilding:
#   SERVICE_NAME=my-api NAMESPACE=prod NODEPORT=31001 TARGET_PORT=8080 ./kube/build-and-install.sh
# Or switch an existing install without reinstall:
#   kubectl set env ds/pod-ip-tracker -c tracker LB_SERVICE_NAME=my-api LB_NAMESPACE=prod
#   kubectl set env ds/pod-ip-tracker -c tc-loader LB_NODEPORT=31001 LB_TARGET_PORT=8080
#
# Speed knobs (push was slow because images were fat + pushed serially):
#   SKIP_BUILD=1   # skip docker entirely, only kubectl apply/set env (fastest)
#   ONLY=tracker|loader  # rebuild/push just one image
#   SKIP_PUSH=1    # build locally only (registry mirror / kind / preloaded nodes)
#   NO_CACHE=1     # disable registry layer cache (default: cache on for fast rebuilds)
#
# Local LAN (no Docker Hub, e.g. 192.168.122.0/24):
#   sudo ./kube/setup-local-registry.sh            # once, starts registry:2 on :5000
#   LOCAL_REGISTRY=192.168.122.100:5000 ./kube/build-and-install.sh
# Zero-registry fallback (scp tarballs + ctr import per node):
#   ./kube/distribute-images.sh "192.168.122.101 192.168.122.102"
#   SKIP_BUILD=1 REGISTRY=local ./kube/build-and-install.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [ -n "${LOCAL_REGISTRY:-}" ]; then
  REGISTRY="$LOCAL_REGISTRY"  # LAN registry wins over Docker Hub default
fi
REGISTRY="${REGISTRY:-fchrgrib}"
TRACKER_IMG="${TRACKER_IMG:-$REGISTRY/pod-ip-tracker:latest}"
LOADER_IMG="${LOADER_IMG:-$REGISTRY/tc-lb-loader:latest}"

SERVICE_NAME="${SERVICE_NAME:-test-service}"
NAMESPACE="${NAMESPACE:-default}"
NODEPORT="${NODEPORT:-30080}"
TARGET_PORT="${TARGET_PORT:-8000}"
LB_IFACE="${LB_IFACE:-}"

ONLY="${ONLY:-all}"
export DOCKER_BUILDKIT=1

# Registry layer cache: rebuilds push only changed layers (much faster 2nd run).
CACHE_ARGS=()
if [ "${NO_CACHE:-0}" != "1" ]; then
  CACHE_ARGS=(--cache-from "type=registry,ref=$TRACKER_IMG" --cache-from "type=registry,ref=$LOADER_IMG")
fi
# Skip attestations: smaller manifests, faster push.
COMMON_ARGS=(--provenance=false --sbom=false "${CACHE_ARGS[@]}")

build_tracker() {
  echo "==> building pod-ip-tracker ($TRACKER_IMG)"
  if [ "${SKIP_PUSH:-0}" = "1" ]; then
    docker build "${COMMON_ARGS[@]}" --cache-to type=inline \
      -f "$ROOT/go/pods_watcher/Dockerfile" -t "$TRACKER_IMG" "$ROOT/go/pods_watcher"
  else
    docker buildx build "${COMMON_ARGS[@]}" --cache-to type=inline --push \
      -f "$ROOT/go/pods_watcher/Dockerfile" -t "$TRACKER_IMG" "$ROOT/go/pods_watcher"
  fi
}

build_loader() {
  echo "==> building tc-loader ($LOADER_IMG)"
  if [ "${SKIP_PUSH:-0}" = "1" ]; then
    docker build "${COMMON_ARGS[@]}" --cache-to type=inline \
      -f "$ROOT/bpf/tc/Dockerfile" -t "$LOADER_IMG" "$ROOT"
  else
    docker buildx build "${COMMON_ARGS[@]}" --cache-to type=inline --push \
      -f "$ROOT/bpf/tc/Dockerfile" -t "$LOADER_IMG" "$ROOT"
  fi
}

if [ "${SKIP_BUILD:-0}" != "1" ]; then
  # Build both images in PARALLEL and push inline (--push): single pass,
  # no separate slow serial `docker push` step.
  case "$ONLY" in
    tracker) build_tracker ;;
    loader)  build_loader ;;
    *)
      build_tracker &
      P1=$!
      build_loader &
      P2=$!
      wait $P1; S1=$?
      wait $P2; S2=$?
      [ $S1 -eq 0 ] && [ $S2 -eq 0 ] || { echo "build failed ($S1/$S2)"; exit 1; }
      ;;
  esac
else
  echo "==> SKIP_BUILD=1: skipping docker build/push"
fi

echo "==> Installing RBAC + DaemonSet from control-plane"
kubectl apply -f "$ROOT/kube/service/pt_rbac.yaml"
# DaemonSet keeps name/selector pod-ip-tracker so existing installs update in place.
kubectl apply -f "$ROOT/kube/service/pt_daemonset.yaml"

# Point the DaemonSet at the images we actually built (Hub default, LAN
# registry, or preloaded `local/` names) — the yaml ships Hub defaults.
kubectl set image ds/pod-ip-tracker \
  "tracker=$TRACKER_IMG" "tc-loader=$LOADER_IMG" --namespace=default || true

echo "==> Applying flexible service/port selection"
kubectl set env ds/pod-ip-tracker -c tracker \
  "LB_SERVICE_NAME=$SERVICE_NAME" "LB_NAMESPACE=$NAMESPACE" --namespace=default || true
kubectl set env ds/pod-ip-tracker -c tc-loader \
  "LB_NODEPORT=$NODEPORT" "LB_TARGET_PORT=$TARGET_PORT" "LB_IFACE=$LB_IFACE" --namespace=default || true

echo "==> Waiting for rollout"
kubectl rollout status daemonset/pod-ip-tracker --timeout=180s

echo "OK: LB now tracks service $NAMESPACE/$SERVICE_NAME on nodeport $NODEPORT -> $TARGET_PORT."
echo "New nodes get a pod automatically; deleting a node removes its pod."
echo "Check with: kubectl get pods -o wide -l app=pod-ip-tracker"
