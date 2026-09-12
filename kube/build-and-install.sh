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
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

REGISTRY="${REGISTRY:-fchrgrib}"
TRACKER_IMG="${TRACKER_IMG:-$REGISTRY/pod-ip-tracker:latest}"
LOADER_IMG="${LOADER_IMG:-$REGISTRY/tc-lb-loader:latest}"

SERVICE_NAME="${SERVICE_NAME:-test-service}"
NAMESPACE="${NAMESPACE:-default}"
NODEPORT="${NODEPORT:-30080}"
TARGET_PORT="${TARGET_PORT:-8000}"
LB_IFACE="${LB_IFACE:-}"

echo "==> 1. Building pod-ip-tracker image ($TRACKER_IMG)"
docker build -f "$ROOT/go/pods_watcher/Dockerfile" -t "$TRACKER_IMG" "$ROOT/go/pods_watcher"

echo "==> 2. Building tc-loader image ($LOADER_IMG)"
docker build -f "$ROOT/bpf/tc/Dockerfile" -t "$LOADER_IMG" "$ROOT"

echo "==> 3. Pushing images (skip with SKIP_PUSH=1)"
if [ "${SKIP_PUSH:-0}" != "1" ]; then
  docker push "$TRACKER_IMG"
  docker push "$LOADER_IMG"
fi

echo "==> 4. Installing RBAC + DaemonSet from control-plane"
kubectl apply -f "$ROOT/kube/service/pt_rbac.yaml"
# DaemonSet keeps name/selector pod-ip-tracker so existing installs update in place.
kubectl apply -f "$ROOT/kube/service/pt_daemonset.yaml"

echo "==> 5. Applying flexible service/port selection"
kubectl set env ds/pod-ip-tracker -c tracker \
  "LB_SERVICE_NAME=$SERVICE_NAME" "LB_NAMESPACE=$NAMESPACE" --namespace=default || true
kubectl set env ds/pod-ip-tracker -c tc-loader \
  "LB_NODEPORT=$NODEPORT" "LB_TARGET_PORT=$TARGET_PORT" "LB_IFACE=$LB_IFACE" --namespace=default || true

echo "==> 6. Waiting for rollout"
kubectl rollout status daemonset/pod-ip-tracker --timeout=180s

echo "OK: LB now tracks service $NAMESPACE/$SERVICE_NAME on nodeport $NODEPORT -> $TARGET_PORT."
echo "New nodes get a pod automatically; deleting a node removes its pod."
echo "Check with: kubectl get pods -o wide -l app=pod-ip-tracker"
