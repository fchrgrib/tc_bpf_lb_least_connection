#!/bin/bash
# Install the active-connection counter (tracepoint) on every node.
# Run from the control-plane. This is the component that makes least-connection
# actually decrement -- without it, hash_map only ever grows.
#
#   ./kube/active_conn/install.sh
#   LOCAL_REGISTRY=192.168.122.100:5000 ./kube/active_conn/install.sh
#   SKIP_PUSH=1 ./kube/active_conn/install.sh
#   SKIP_BUILD=1 REGISTRY=local ./kube/active_conn/install.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

if [ -n "${LOCAL_REGISTRY:-}" ]; then
  REGISTRY="$LOCAL_REGISTRY"
fi
REGISTRY="${REGISTRY:-fchrgrib}"
IMG="${ACTIVE_CONN_IMG:-$REGISTRY/active-conn:latest}"
NS="${NAMESPACE:-default}"

export DOCKER_BUILDKIT=1

if [ "${SKIP_BUILD:-0}" != "1" ]; then
  echo "==> Building active-conn ($IMG)"
  if [ "${SKIP_PUSH:-0}" = "1" ]; then
    docker build --provenance=false --sbom=false \
      -f "$ROOT/go/trace/Dockerfile" -t "$IMG" "$ROOT"
  else
    docker buildx build --provenance=false --sbom=false --push \
      -f "$ROOT/go/trace/Dockerfile" -t "$IMG" "$ROOT"
  fi
else
  echo "==> SKIP_BUILD=1: skipping docker build/push"
fi

echo "==> Applying ServiceAccount + DaemonSet (namespace=$NS)"
kubectl -n "$NS" apply -f "$ROOT/kube/active_conn/rbac.yaml"
sed "s|__IMAGE__|$IMG|g" "$ROOT/kube/active_conn/daemonset.yaml" | kubectl -n "$NS" apply -f -

echo "==> Waiting for rollout"
kubectl -n "$NS" rollout status ds/active-conn --timeout=180s

echo
echo "OK. Verify the chain:"
echo "  kubectl -n $NS get pods -o wide -l app=active-conn"
echo "  kubectl -n $NS logs -l app=active-conn --tail=20"
echo "     expect: 'attached tracepoint sock/inet_sock_set_state'"
echo
echo "Then confirm counts rise AND fall (needs map_sync running for hash_map):"
echo "  # on a node: bpftool map dump name hash_map"
