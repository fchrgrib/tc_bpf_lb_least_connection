#!/bin/bash
# Install map_sync with mTLS + NetworkPolicy.
# Run from the control-plane (needs kubectl + docker, and a cert-manager install).
#
#   ./kube/map_sync/install.sh
#   REGISTRY=192.168.122.100:5000 ./kube/map_sync/install.sh
#   SKIP_PUSH=1 ./kube/map_sync/install.sh        # image already on nodes
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

REGISTRY="${REGISTRY:-fchrgrib}"
IMG="${MAP_SYNC_IMG:-$REGISTRY/map-sync:latest}"
NS="default"

echo "==> 1/6 Checking cert-manager"
if ! kubectl get ns cert-manager >/dev/null 2>&1; then
  echo "ERROR: cert-manager not found. Install it first:"
  echo "  kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.15.3/cert-manager.yaml"
  echo "  kubectl -n cert-manager wait --for=condition=Available deploy --all --timeout=180s"
  exit 1
fi
echo "    cert-manager present"

echo "==> 2/6 Building image $IMG"
docker build --provenance=false --sbom=false \
  -f "$ROOT/go/map_sync/Dockerfile" -t "$IMG" "$ROOT"
if [ "${SKIP_PUSH:-0}" != "1" ]; then
  docker push "$IMG"
fi

echo "==> 3/6 Applying issuer + CA (cert-manager namespace)"
kubectl apply -f "$ROOT/kube/map_sync/cert-manager.yaml"
kubectl -n cert-manager wait --for=condition=Ready certificate/map-sync-ca --timeout=180s

echo "==> 4/6 Applying ServiceAccount, Service, Certificate, NetworkPolicy"
kubectl -n "$NS" apply -f "$ROOT/kube/map_sync/rbac.yaml"
kubectl -n "$NS" apply -f "$ROOT/kube/map_sync/service.yaml"
kubectl -n "$NS" apply -f "$ROOT/kube/map_sync/certificate.yaml"
kubectl -n "$NS" apply -f "$ROOT/kube/map_sync/networkpolicy.yaml"
kubectl -n "$NS" wait --for=condition=Ready certificate/map-sync-tls --timeout=180s

echo "==> 5/6 Applying DaemonSet (image=$IMG)"
sed "s|__IMAGE__|$IMG|g" "$ROOT/kube/map_sync/daemonset.yaml" | kubectl -n "$NS" apply -f -

echo "==> 6/6 Waiting for rollout"
kubectl -n "$NS" rollout status ds/map-sync --timeout=180s

echo
echo "OK. Verify:"
echo "  kubectl -n $NS get pods -o wide -l app=map-sync"
echo "  kubectl -n $NS get certificate"
echo "  kubectl -n $NS logs -l app=map-sync --tail=20"
echo "  kubectl -n $NS get networkpolicy map-sync"
