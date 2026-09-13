#!/bin/bash
# Zero-registry fallback: build once, save tarballs, copy over LAN and import
# directly into each node's container runtime. Nothing leaves 192.168.122.0/24.
#
#   SSH_USER=fadholi ./kube/distribute-images.sh "192.168.122.101 192.168.122.102"
#   # then: SKIP_BUILD=1 ./kube/build-and-install.sh  (images already present,
#   # DaemonSet uses imagePullPolicy IfNotPresent so no pull is attempted)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NODES="${1:-${NODES:-}}"
[ -n "$NODES" ] || { echo "usage: $0 \"<node-ip-1> <node-ip-2>...\""; exit 1; }
# SSH login user (NOT root unless you mean it). NODES entries may also be
# user@host to override per-node.
SSH_USER="${SSH_USER:-${USER:-fadholi}}"

REGISTRY="${REGISTRY:-local}"
TRACKER_IMG="$REGISTRY/pod-ip-tracker:latest"
LOADER_IMG="$REGISTRY/tc-lb-loader:latest"
OUTDIR="${OUTDIR:-/tmp/lb-images}"
mkdir -p "$OUTDIR"

echo "==> Building locally (no push)"
export DOCKER_BUILDKIT=1
docker build --provenance=false --sbom=false \
  -f "$ROOT/go/pods_watcher/Dockerfile" -t "$TRACKER_IMG" "$ROOT/go/pods_watcher"
docker build --provenance=false --sbom=false \
  -f "$ROOT/bpf/tc/Dockerfile" -t "$LOADER_IMG" "$ROOT"

echo "==> Saving tarballs"
docker save -o "$OUTDIR/pod-ip-tracker.tar" "$TRACKER_IMG"
docker save -o "$OUTDIR/tc-lb-loader.tar" "$LOADER_IMG"
ls -lh "$OUTDIR"

for N in $NODES; do
  # Allow "user@host" per entry, else prepend SSH_USER (scp/ssh default to
  # local $USER, and bare IPs otherwise fall back to root on some setups).
  case "$N" in
    *@*) DEST="$N" ;;
    *) DEST="$SSH_USER@$N" ;;
  esac
  echo "==> Copying to $DEST"
  scp "$OUTDIR"/pod-ip-tracker.tar "$OUTDIR"/tc-lb-loader.tar "$DEST:/tmp/"
  echo "==> Importing on $DEST (tries crictl/containerd, falls back to docker)"
  ssh "$DEST" "sudo bash -s" <<'REMOTE'
set -x
if command -v ctr >/dev/null; then
  sudo ctr -n k8s.io images import /tmp/pod-ip-tracker.tar || true
  sudo ctr -n k8s.io images import /tmp/tc-lb-loader.tar || true
elif command -v crictl >/dev/null; then
  sudo crictl load -i /tmp/pod-ip-tracker.tar || true
  sudo crictl load -i /tmp/tc-lb-loader.tar || true
else
  sudo docker load -i /tmp/pod-ip-tracker.tar
  sudo docker load -i /tmp/tc-lb-loader.tar
fi
REMOTE
done

cat <<EOF
Done. Images are preloaded on all nodes.
Now install WITHOUT building/pushing (DaemonSet is IfNotPresent, no pull):
  SKIP_BUILD=1 REGISTRY=$REGISTRY TRACKER_IMG=$TRACKER_IMG LOADER_IMG=$LOADER_IMG ./kube/build-and-install.sh
NOTE: build-and-install.sh will kubectl set image to $REGISTRY/... so the
DaemonSet references the preloaded names. New nodes joining later need the same
import (re-run this script with the new node IP), or switch to the local-registry
flow (kube/setup-local-registry.sh) so pulls are automatic.
EOF
