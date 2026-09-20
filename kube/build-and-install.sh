#!/bin/bash
# Build + install the TC eBPF LB from the control-plane.
# Run once on control-plane. After that, new nodes get the LB automatically
# via the DaemonSet, and removed nodes are cleaned up automatically.
#
# Base LB only (tracker + tc-loader):
#   ./kube/build-and-install.sh
#
# Everything (base LB + active-conn + map_sync) in one command:
#   ./kube/build-and-install.sh --all
#
# A single optional component (replaces the old per-component install.sh):
#   ONLY=active-conn ./kube/build-and-install.sh
#   ONLY=map-sync    ./kube/build-and-install.sh
#
# Flexible: pick any Service + NodePort without rebuilding:
#   SERVICE_NAME=my-api NAMESPACE=prod NODEPORT=31001 TARGET_PORT=8080 ./kube/build-and-install.sh
# Or switch an existing install without reinstall:
#   kubectl set env ds/pod-ip-tracker -c tracker LB_SERVICE_NAME=my-api LB_NAMESPACE=prod
#   kubectl set env ds/pod-ip-tracker -c tc-loader LB_NODEPORT=31001 LB_TARGET_PORT=8080
#
# Speed knobs:
#   SKIP_BUILD=1   # skip docker entirely, only kubectl apply/set env (fastest)
#   ONLY=<comp>    # target one component: tracker|loader|active-conn|map-sync
#                  #   (build that image and install only that component)
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

# --all flag: install everything (base LB + active-conn + map_sync)
ALL="${ALL:-0}"
for arg in "$@"; do
  case "$arg" in
    --all) ALL=1 ;;
  esac
done

if [ -n "${LOCAL_REGISTRY:-}" ]; then
  REGISTRY="$LOCAL_REGISTRY"
fi
REGISTRY="${REGISTRY:-fchrgrib}"
TRACKER_IMG="${TRACKER_IMG:-$REGISTRY/pod-ip-tracker:latest}"
LOADER_IMG="${LOADER_IMG:-$REGISTRY/tc-lb-loader:latest}"
ACTIVE_CONN_IMG="${ACTIVE_CONN_IMG:-$REGISTRY/active-conn:latest}"
MAP_SYNC_IMG="${MAP_SYNC_IMG:-$REGISTRY/map-sync:latest}"

SERVICE_NAME="${SERVICE_NAME:-test-service}"
NODEPORT="${NODEPORT:-30080}"
TARGET_PORT="${TARGET_PORT:-8000}"
LB_IFACE="${LB_IFACE:-}"

ONLY="${ONLY:-all}"
export DOCKER_BUILDKIT=1

# Registry layer cache: rebuilds push only changed layers (much faster 2nd run).
CACHE_ARGS=()
if [ "${NO_CACHE:-0}" != "1" ]; then
  CACHE_ARGS=(--cache-from "type=registry,ref=$TRACKER_IMG" --cache-from "type=registry,ref=$LOADER_IMG" --cache-from "type=registry,ref=$ACTIVE_CONN_IMG")
fi
COMMON_ARGS=(--provenance=false --sbom=false "${CACHE_ARGS[@]}")

build_tracker() {
  echo "==> building pod-ip-tracker ($TRACKER_IMG)"
  if [ "${SKIP_PUSH:-0}" = "1" ]; then
    docker build "${COMMON_ARGS[@]}" --cache-to type=inline \
      -f "$ROOT/bpf/user_space/pods_watcher/Dockerfile" -t "$TRACKER_IMG" "$ROOT/bpf/user_space"
  else
    docker buildx build "${COMMON_ARGS[@]}" --cache-to type=inline --push \
      -f "$ROOT/bpf/user_space/pods_watcher/Dockerfile" -t "$TRACKER_IMG" "$ROOT/bpf/user_space"
  fi
}

build_loader() {
  echo "==> building tc-loader ($LOADER_IMG)"
  if [ "${SKIP_PUSH:-0}" = "1" ]; then
    docker build "${COMMON_ARGS[@]}" --cache-to type=inline \
      -f "$ROOT/bpf/user_space/tc/Dockerfile" -t "$LOADER_IMG" "$ROOT"
  else
    docker buildx build "${COMMON_ARGS[@]}" --cache-to type=inline --push \
      -f "$ROOT/bpf/user_space/tc/Dockerfile" -t "$LOADER_IMG" "$ROOT"
  fi
}

build_active_conn() {
  echo "==> building active-conn ($ACTIVE_CONN_IMG)"
  if [ "${SKIP_PUSH:-0}" = "1" ]; then
    docker build "${COMMON_ARGS[@]}" --cache-to type=inline \
      -f "$ROOT/bpf/user_space/trace/Dockerfile" -t "$ACTIVE_CONN_IMG" "$ROOT"
  else
    docker buildx build "${COMMON_ARGS[@]}" --cache-to type=inline --push \
      -f "$ROOT/bpf/user_space/trace/Dockerfile" -t "$ACTIVE_CONN_IMG" "$ROOT"
  fi
}

build_map_sync() {
  echo "==> building map-sync ($MAP_SYNC_IMG)"
  if [ "${SKIP_PUSH:-0}" = "1" ]; then
    docker build "${COMMON_ARGS[@]}" --cache-to type=inline \
      -f "$ROOT/bpf/user_space/map_sync/Dockerfile" -t "$MAP_SYNC_IMG" "$ROOT"
  else
    docker buildx build "${COMMON_ARGS[@]}" --cache-to type=inline --push \
      -f "$ROOT/bpf/user_space/map_sync/Dockerfile" -t "$MAP_SYNC_IMG" "$ROOT"
  fi
}

resolve_ref() {
  local ref="$1"
  [ "${PIN_DIGEST:-1}" = "1" ] || { echo "$ref"; return; }
  [ "${SKIP_PUSH:-0}" = "1" ] && { echo "$ref"; return; }
  local repo="${ref%:*}"
  local digest
  digest=$(docker buildx imagetools inspect "$ref" --format '{{.Manifest.Digest}}' 2>/dev/null || true)
  if [ -n "$digest" ]; then echo "${repo}@${digest}"; else echo "$ref"; fi
}

# ── Build ────────────────────────────────────────────────────────────────────
if [ "${SKIP_BUILD:-0}" != "1" ]; then
  # lib/ deps are git submodules; a fresh clone without `git submodule update`
  # would otherwise fail deep inside clang with a confusing missing-header error.
  for f in lib/libbpf/src/bpf_helpers.h lib/vmlinux.h/include/x86/vmlinux.h; do
    if [ ! -e "$ROOT/$f" ]; then
      echo "ERROR: $f is missing — dependencies are git submodules. Run:"
      echo "  git submodule update --init --recursive"
      exit 1
    fi
  done
  case "$ONLY" in
    tracker)     build_tracker ;;
    loader)      build_loader ;;
    active-conn) build_active_conn ;;
    map-sync)    build_map_sync ;;
    *)
      build_tracker & P1=$!
      build_loader  & P2=$!
      [ "$ALL" = "1" ] && { build_active_conn & P3=$!; build_map_sync & P4=$!; }
      wait $P1; S1=$?
      wait $P2; S2=$?
      [ "$ALL" = "1" ] && { wait $P3; S3=$?; wait $P4; S4=$?; } || { S3=0; S4=0; }
      [ $S1 -eq 0 ] && [ $S2 -eq 0 ] && [ $S3 -eq 0 ] && [ $S4 -eq 0 ] \
        || { echo "build failed ($S1/$S2/$S3/$S4)"; exit 1; }
      ;;
  esac
else
  echo "==> SKIP_BUILD=1: skipping docker build/push"
fi

# ── Decide what to install ──────────────────────────────────────────────────
#   default           -> base LB (tracker + tc-loader)
#   --all             -> base LB + active-conn + map_sync
#   ONLY=active-conn  -> active-conn only
#   ONLY=map-sync     -> map_sync only
if [ "$ALL" = "1" ]; then
  INSTALL_BASE=1; INSTALL_ACTIVE=1; INSTALL_MAPSYNC=1
else
  case "$ONLY" in
    active-conn) INSTALL_BASE=0; INSTALL_ACTIVE=1; INSTALL_MAPSYNC=0 ;;
    map-sync)    INSTALL_BASE=0; INSTALL_ACTIVE=0; INSTALL_MAPSYNC=1 ;;
    *)           INSTALL_BASE=1; INSTALL_ACTIVE=0; INSTALL_MAPSYNC=0 ;;
  esac
fi

# ── Install base LB (tracker + tc-loader) ───────────────────────────────────
if [ "$INSTALL_BASE" = "1" ]; then
  echo "==> Installing base LB: namespace-scoped RBAC + DaemonSet (namespace=$NS)"
  kubectl delete clusterrole/pod-ip-tracker clusterrolebinding/pod-ip-tracker \
    --ignore-not-found >/dev/null 2>&1 || true
  sed "s|__NAMESPACE__|$NS|g" "$ROOT/kube/service/pt_rbac.yaml" | kubectl apply -n "$NS" -f -
  kubectl apply -n "$NS" -f "$ROOT/kube/service/pt_daemonset.yaml"

  echo "==> Pinning base LB images (digest where possible)"
  TRACKER_REF="$(resolve_ref "$TRACKER_IMG")"
  LOADER_REF="$(resolve_ref "$LOADER_IMG")"
  kubectl -n "$NS" set image ds/pod-ip-tracker \
    "tracker=$TRACKER_REF" "tc-loader=$LOADER_REF" || true

  echo "==> Applying flexible service/port selection"
  kubectl -n "$NS" set env ds/pod-ip-tracker -c tracker \
    "LB_SERVICE_NAME=$SERVICE_NAME" "LB_NAMESPACE=$NS" || true
  kubectl -n "$NS" set env ds/pod-ip-tracker -c tc-loader \
    "LB_NODEPORT=$NODEPORT" "LB_TARGET_PORT=$TARGET_PORT" "LB_IFACE=$LB_IFACE" || true

  echo "==> Waiting for base LB rollout"
  kubectl -n "$NS" rollout status daemonset/pod-ip-tracker --timeout=180s
fi

# ── Install active-conn ─────────────────────────────────────────────────────
if [ "$INSTALL_ACTIVE" = "1" ]; then
  echo "==> Installing active-conn DaemonSet"
  kubectl -n "$NS" apply -f "$ROOT/kube/active_conn/rbac.yaml"
  ACTIVE_CONN_REF="$(resolve_ref "$ACTIVE_CONN_IMG")"
  sed "s|__IMAGE__|$ACTIVE_CONN_REF|g" "$ROOT/kube/active_conn/daemonset.yaml" \
    | kubectl -n "$NS" apply -f -

  echo "==> Waiting for active-conn rollout"
  kubectl -n "$NS" rollout status ds/active-conn --timeout=180s
fi

# ── Install map_sync (requires cert-manager) ────────────────────────────────
if [ "$INSTALL_MAPSYNC" = "1" ]; then
  echo "==> Installing map_sync with mTLS"
  if ! kubectl get ns cert-manager >/dev/null 2>&1; then
    echo "ERROR: cert-manager not found. Install it first:"
    echo "  kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.15.3/cert-manager.yaml"
    echo "  kubectl -n cert-manager wait --for=condition=Available deploy --all --timeout=180s"
    exit 1
  fi

  echo "==> Applying map_sync cert-manager issuer + CA"
  kubectl apply -f "$ROOT/kube/map_sync/cert-manager.yaml"
  kubectl -n cert-manager wait --for=condition=Ready certificate/map-sync-ca --timeout=180s

  echo "==> Applying map_sync RBAC, Service, Certificate, NetworkPolicy"
  kubectl -n "$NS" apply -f "$ROOT/kube/map_sync/rbac.yaml"
  kubectl -n "$NS" apply -f "$ROOT/kube/map_sync/service.yaml"
  kubectl -n "$NS" apply -f "$ROOT/kube/map_sync/certificate.yaml"
  kubectl -n "$NS" apply -f "$ROOT/kube/map_sync/networkpolicy.yaml"
  kubectl -n "$NS" wait --for=condition=Ready certificate/map-sync-tls --timeout=180s

  echo "==> Applying map_sync DaemonSet"
  MAP_SYNC_REF="$(resolve_ref "$MAP_SYNC_IMG")"
  sed "s|__IMAGE__|$MAP_SYNC_REF|g" "$ROOT/kube/map_sync/daemonset.yaml" \
    | kubectl -n "$NS" apply -f -

  echo "==> Waiting for map_sync rollout"
  kubectl -n "$NS" rollout status ds/map-sync --timeout=180s
fi

echo
echo "OK."
[ "$INSTALL_BASE" = "1" ] && echo "  base LB:    service $NS/$SERVICE_NAME nodeport $NODEPORT -> $TARGET_PORT"
[ "$INSTALL_ACTIVE" = "1" ] && echo "  active-conn installed"
[ "$INSTALL_MAPSYNC" = "1" ] && echo "  map-sync    installed"
echo "  new nodes get a pod automatically; deleting a node removes its pod."
echo "  check with: kubectl get pods -o wide -n $NS"
