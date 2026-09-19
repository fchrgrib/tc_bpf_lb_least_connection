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
# Speed knobs:
#   SKIP_BUILD=1   # skip docker entirely, only kubectl apply/set env (fastest)
#   ONLY=tracker|loader  # rebuild/push just one image
#   SKIP_PUSH=1    # build locally only (registry mirror / kind / preloaded nodes)
#   NO_CACHE=1     # disable registry layer cache (default: cache on)
#   PIN_DIGEST=0   # don't pin images by @sha256 (default: pin after push)
#
# Local LAN (no Docker Hub, e.g. 192.168.122.0/24):
#   sudo ./kube/setup-local-registry.sh            # once, starts registry:2 on :5000
#   LOCAL_REGISTRY=192.168.122.100:5000 ./kube/build-and-install.sh
# Zero-registry fallback (scp tarballs + ctr import per node):
#   ./kube/distribute-images.sh "192.168.122.101 192.168.122.102"
#   SKIP_BUILD=1 REGISTRY=local ./kube/build-and-install.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Namespace is applied consistently to RBAC, DaemonSet, and set env/image.
NS="${NAMESPACE:-default}"

if [ -n "${LOCAL_REGISTRY:-}" ]; then
  REGISTRY="$LOCAL_REGISTRY"  # LAN registry wins over Docker Hub default
fi
REGISTRY="${REGISTRY:-fchrgrib}"
TRACKER_IMG="${TRACKER_IMG:-$REGISTRY/pod-ip-tracker:latest}"
LOADER_IMG="${LOADER_IMG:-$REGISTRY/tc-lb-loader:latest}"

SERVICE_NAME="${SERVICE_NAME:-test-service}"
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
COMMON_ARGS=(--provenance=false --sbom=false "${CACHE_ARGS[@]}")

build_tracker() {
  echo "==> building pod-ip-tracker ($TRACKER_IMG)"
  if [ "${SKIP_PUSH:-0}" = "1" ]; then
    docker build "${COMMON_ARGS[@]}" --cache-to type=inline \
      -f "$ROOT/go/pods_watcher/Dockerfile" -t "$TRACKER_IMG" "$ROOT/go"
  else
    docker buildx build "${COMMON_ARGS[@]}" --cache-to type=inline --push \
      -f "$ROOT/go/pods_watcher/Dockerfile" -t "$TRACKER_IMG" "$ROOT/go"
  fi
}

build_loader() {
  echo "==> building tc-loader ($LOADER_IMG)"
  if [ "${SKIP_PUSH:-0}" = "1" ]; then
    docker build "${COMMON_ARGS[@]}" --cache-to type=inline \
      -f "$ROOT/go/tc/Dockerfile" -t "$LOADER_IMG" "$ROOT"
  else
    docker buildx build "${COMMON_ARGS[@]}" --cache-to type=inline --push \
      -f "$ROOT/go/tc/Dockerfile" -t "$LOADER_IMG" "$ROOT"
  fi
}

# Resolve repo@sha256:<digest> so the DaemonSet runs an immutable image.
# Falls back to the tag when the registry can't be inspected (e.g. insecure LAN).
resolve_ref() {
  local ref="$1"
  [ "${PIN_DIGEST:-1}" = "1" ] || { echo "$ref"; return; }
  [ "${SKIP_PUSH:-0}" = "1" ] && { echo "$ref"; return; }
  local repo="${ref%:*}"
  local digest
  digest=$(docker buildx imagetools inspect "$ref" --format '{{.Manifest.Digest}}' 2>/dev/null || true)
  if [ -n "$digest" ]; then echo "${repo}@${digest}"; else echo "$ref"; fi
}

if [ "${SKIP_BUILD:-0}" != "1" ]; then
  case "$ONLY" in
    tracker) build_tracker ;;
    loader)  build_loader ;;
    *)
      build_tracker & P1=$!
      build_loader  & P2=$!
      wait $P1; S1=$?
      wait $P2; S2=$?
      [ $S1 -eq 0 ] && [ $S2 -eq 0 ] || { echo "build failed ($S1/$S2)"; exit 1; }
      ;;
  esac
else
  echo "==> SKIP_BUILD=1: skipping docker build/push"
fi

echo "==> Installing namespace-scoped RBAC + DaemonSet (namespace=$NS)"
# Remove the old cluster-wide grants from previous installs (best effort).
kubectl delete clusterrole/pod-ip-tracker clusterrolebinding/pod-ip-tracker \
  --ignore-not-found >/dev/null 2>&1 || true
# RBAC is now a Role/RoleBinding in the target namespace (not cluster-wide).
sed "s|__NAMESPACE__|$NS|g" "$ROOT/kube/service/pt_rbac.yaml" | kubectl apply -n "$NS" -f -
kubectl apply -n "$NS" -f "$ROOT/kube/service/pt_daemonset.yaml"

echo "==> Pinning images (digest where possible)"
TRACKER_REF="$(resolve_ref "$TRACKER_IMG")"
LOADER_REF="$(resolve_ref "$LOADER_IMG")"
kubectl -n "$NS" set image ds/pod-ip-tracker \
  "tracker=$TRACKER_REF" "tc-loader=$LOADER_REF" || true

echo "==> Applying flexible service/port selection"
kubectl -n "$NS" set env ds/pod-ip-tracker -c tracker \
  "LB_SERVICE_NAME=$SERVICE_NAME" "LB_NAMESPACE=$NS" || true
kubectl -n "$NS" set env ds/pod-ip-tracker -c tc-loader \
  "LB_NODEPORT=$NODEPORT" "LB_TARGET_PORT=$TARGET_PORT" "LB_IFACE=$LB_IFACE" || true

echo "==> Waiting for rollout"
kubectl -n "$NS" rollout status daemonset/pod-ip-tracker --timeout=180s

echo "OK: LB now tracks service $NS/$SERVICE_NAME on nodeport $NODEPORT -> $TARGET_PORT."
echo "New nodes get a pod automatically; deleting a node removes its pod."
echo "Check with: kubectl get pods -o wide -l app=pod-ip-tracker -n $NS"
