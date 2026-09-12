#!/bin/bash
# Start a local (insecure, LAN-only) registry on this control-plane and print
# the per-node config so every 192.168.122.0/24 node can pull from it.
# No Docker Hub account, no internet push — pulls stay on your gigabit LAN.
#
#   sudo ./kube/setup-local-registry.sh
#   # then on EACH node (worker + control-plane), run the printed commands
#   # then: LOCAL_REGISTRY=192.168.122.100:5000 ./kube/build-and-install.sh
set -euo pipefail

REGISTRY_HOST="${REGISTRY_HOST:-$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -n1)}"
REGISTRY_HOST="${REGISTRY_HOST:-192.168.122.100}"
PORT="${REGISTRY_PORT:-5000}"
ADDR="$REGISTRY_HOST:$PORT"

echo "==> Starting local registry at $ADDR"
docker run -d --restart always --name local-registry -p "$PORT:5000" \
  -v registry-data:/var/lib/registry registry:2 2>/dev/null \
  || docker start local-registry
sleep 2
curl -sf "http://$ADDR/v2/" >/dev/null && echo "OK: registry up at $ADDR"

cat <<EOF

=================== RUN ON EACH NODE (workers + control-plane) ===================

# A. If nodes use Docker:
sudo tee /etc/docker/daemon.json >/dev/null <<JSON
{
  "insecure-registries": ["$ADDR"]
}
JSON
sudo systemctl restart docker

# B. If nodes use containerd (default for kubeadm / k8s 1.24+):
sudo mkdir -p /etc/containerd/certs.d/$ADDR
sudo tee /etc/containerd/certs.d/$ADDR/hosts.toml >/dev/null <<TOML
server = "http://$ADDR"
[host."http://$ADDR"]
  capabilities = ["pull", "resolve", "push"]
  skip_verify = true
TOML
# and ensure /etc/containerd/config.toml has:
#   [plugins."io.containerd.grpc.v1.cri".registry]
#     config_path = "/etc/containerd/certs.d"
sudo systemctl restart containerd

# Test from a node:
crictl pull $ADDR/pod-ip-tracker:latest || docker pull $ADDR/pod-ip-tracker:latest
==================================================================================

Then install with:
  LOCAL_REGISTRY=$ADDR ./kube/build-and-install.sh
EOF
