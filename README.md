# Load Balancer Least Connection eBPF Kubernetes

TC eBPF load balancer with least-connection selection, deployed as a Kubernetes
`DaemonSet`. Install once from the control-plane — every current and future node
gets the LB automatically, and removed nodes are cleaned up automatically.

## What is this project for

Kubernetes Services (`ClusterIP`/`NodePort` via kube-proxy iptables/IPVS) spread
traffic round-robin/randomly. That is fine for short stateless requests, but bad
when connections are **long-lived or uneven** (e.g. your Flask backends holding
open connections, WebSockets, keep-alive APIs): one Pod can pile up connections
while others sit idle.

This project replaces that decision point **per node, inside the kernel**:

1. `tracker` (`go/pods_watcher/`) watches your Service's ready Pod IPs through
   the K8s API and keeps them in a pinned eBPF map
   (`/sys/fs/bpf/service_pod_ips`) — always current as Pods scale/churn.
2. The TC program (`bpf/tc/tc.bpf.c`) attaches at **ingress** on each node's
   physical iface. For a new TCP/UDP flow to your `nodePort`, it DNATs the
   packet to the currently least-loaded backend (plus SNAT/masquerade) using
   kernel conntrack (`bpf_skb_ct_*`), so return traffic works with no userspace hop.
3. The loader (`bpf/tc/tc.c`) re-evaluates every 2s: it reads live backend IPs
   plus per-backend connection counts (`hash_map`, optionally synced across
   nodes by `go/map_sync/` via fentry + gRPC) and writes the winner into the
   `selected` map the datapath reads.

In short: **any traffic hitting `<any-node-ip>:<nodePort>` gets steered in-kernel
to whichever backend Pod currently holds the fewest connections.**

## Benefits of installing it on your Services

- **Least-connection instead of round-robin.** Busy Pods get fewer new flows,
  idle Pods get more — higher throughput and fewer tail-latency spikes under
  uneven load, without changing app code.
- **Runs in kernel at TC ingress.** No extra userspace proxy (Envoy/HAProxy
  sidecar) or external LB box in the path per packet — lower per-packet latency
  and CPU than hopping through additional proxies.
- **Per-node, no single choke point.** Every node makes the decision locally for
  traffic it receives. Capacity grows with nodes, and there is no separate LB
  tier to size, HA-configure, or pay a cloud provider for (useful on bare
  metal / on-prem where `LoadBalancer` Services have no cloud implementation).
- **Pod-churn aware.** Backend set follows the Service endpoints via API watch
  (ready Pods only, 15-min resync as backup), so scaling your Deployment up/down
  or rolling updates don't leave stale backends.
- **Zero-touch scaling of the LB itself.** DaemonSet = new nodes self-install,
  removed nodes self-clean (`SIGTERM` detach + `preStop` qdisc removal). One
  manifest works for any Service/NodePort via env (`LB_SERVICE_NAME`,
  `LB_NAMESPACE`, `LB_NODEPORT`, `LB_TARGET_PORT`).
- **Cheap to try per Service.** Point it at one `NodePort` Service first
  (e.g. the heaviest long-connection API), leave the rest on kube-proxy.

- **Cheap to try per Service.** Point it at one `NodePort` Service first
  (e.g. the heaviest long-connection API), leave the rest on kube-proxy.

## Limitations (please read before production use)

- **One Service per DaemonSet install.** The tracker watches a single
  `LB_SERVICE_NAME`/`LB_NAMESPACE`, and `svc_map` holds the active NodePort.
  Balancing N Services needs N DaemonSet copies (different names/selectors) or
  a multi-service extension.
- **NodePort Services only.** No `ClusterIP`-only or `LoadBalancer` support;
  `LB_NODEPORT` (1–65535) must equal the Service's `nodePort`, `LB_TARGET_PORT`
  must equal its `targetPort`/`containerPort`.
- **IPv4 TCP/UDP only.** The datapath (`tc.bpf.c`) parses `ETH_P_IP` + TCP/UDP
  tuples; other protocols pass through untouched, IPv6 is not NATed.
- **Kernel requirement.** Needs TC-BPF with `clsact` plus `bpf_skb_ct_*`
  conntrack kfuncs (recent kernels, e.g. 6.x with `CONFIG_NETFILTER` conntrack).
  Old kernels fail at load/attach time.
- **Privileged per-node agent.** Requires `privileged: true`, `hostNetwork`,
  `BPF`/`NET_ADMIN`/`SYS_ADMIN` caps, and host mounts (`/lib/modules`,
  `/sys/fs/bpf`). This is the standard eBPF-DaemonSet tradeoff: full node power
  in exchange for kernel access.
- **Static fallback is 2 backends; scale cap ~100 Pods.** `svc_map` carries only
  `be1/be2` as fallback (live set comes from the tracker map, capped at 100
  entries in `ebpfMapSpec`), `hash_map` at 10240 entries. Tune `MaxEntries` for
  larger fleets.
- **Eventual consistency (~2s + resync).** Backend election runs every 2s and the
  Pod watch resyncs every 15 min as backup — brief imbalance is possible right
  after scale/rollout events.
- **Per-node counts by default.** Without deploying `go/map_sync/` (fentry +
  gRPC peer sync, not included in the DaemonSet), each node balances on locally
  observed connection counts rather than a global view.
- **No L7 features.** No TLS termination, header/path routing, retries, rate
  limiting, or Prometheus metrics — it is a pure L3/L4 least-conn steerer.
  Health checking = K8s readiness only (unready Pods are excluded on next sync).
- **One iface per node + runs on control-plane too.** `LB_IFACE` is a single
  iface (auto-detected default route); multi-NIC/dual-plane nodes need explicit
  config. The DaemonSet tolerates all taints, so control-plane nodes also get a
  Pod unless you add a `nodeAffinity`.
- **Hard node death can leave `clsact`.** Graceful drain cleans up via `SIGTERM`
  + `preStop`; a crashed node needs manual `tc qdisc del dev <iface> clsact` and
  stale `/sys/fs/bpf/*` removal (see Uninstall).

## Why eBPF, and what it buys you here

eBPF lets you run small verified programs **inside the kernel** at hook points
like TC ingress — no kernel rebuild, no module, detachable at runtime. This
project uses exactly that:

- **Datapath in kernel (`bpf/tc/tc.bpf.c`, hook `tc_ingress`).** Every packet to
  your `nodePort` is inspected before it climbs the normal stack. New flows get
  NAT decision + connection counting via eBPF maps (`svc_map`, `hash_map`,
  `selected`); established flows hit existing conntrack entries and pass
  through. No per-packet trip to userspace.
- **Control plane in userspace.** K8s watch (`tracker`), least-conn election
  (`tc.c` loop), and cross-node sync (`map_sync` fentry on map updates + gRPC)
  just read/write those same maps. Kernel and userspace share state through
  maps, not syscalls per packet.

Benefits over the usual alternatives:

| Approach | What changes with this eBPF design |
|---|---|
| iptables/IPVS kube-proxy | No giant rule chains to traverse/update on Pod churn; decision is one map lookup + conntrack insert. Updates are map writes, not rule rewrites. Programmable policy (least-conn here, anything later) instead of fixed round-robin. |
| Userspace reverse proxy (HAProxy/Envoy/sidecar) | No extra proxy hop, no context switches or packet copies per request, lower p99 latency and CPU at high pps. LB scales with nodes instead of sizing a proxy tier. |
| External/cloud LB | No extra network hop or provider dependency — matters on bare metal/on-prem where `type: LoadBalancer` has no implementation. |
| Kernel module / custom build | eBPF is verified + sandboxed by the kernel, ships as a container, attaches/detaches live (`bpf_tc_attach`/`detach`), no node reboot or custom kernel. |

Net effect for your Services: **per-packet work stays in the kernel fast path,
policy stays flexible in userspace maps** — least-connection accuracy of a smart
proxy with overhead closer to plain forwarding.

## How it works

Two containers run together on **every node** via one DaemonSet
(`kube/service/pt_daemonset.yaml`, name `pod-ip-tracker`):

| Container | Image | Job |
|---|---|---|
| `tracker` | `fchrgrib/pod-ip-tracker:latest` (built from `go/pods_watcher/`) | Watches `test-service` Pods via the K8s API, maintains pinned map `/sys/fs/bpf/service_pod_ips` |
| `tc-loader` | `fchrgrib/tc-lb-loader:latest` (built from `bpf/tc/`) | Attaches the TC eBPF program (`tc.bpf.c`) to the host iface, picks the least-connection backend every 2s |

Supporting pieces:

- `kube/service/pt_rbac.yaml` — ServiceAccount + ClusterRole (`get,list,watch` on `pods,services`) + Binding.
- `kube/service/lb_service.yaml` — demo `NodePort` Service (`nodePort: 30080`, `targetPort: 8000`).
- `kube/service/backend.yaml` — demo backend Deployment (3x `flask-backend` on port 8000).
- `bpf/tc/entrypoint.sh` — auto-detects the host iface per node (see Configuration).
- `kube/build-and-install.sh` — one-shot build + install script.

Auto-scale behavior is native Kubernetes: the DaemonSet controller creates one Pod
per matching node on join (`Ready`) and garbage-collects the Pod on node
delete/drain. The `tc-loader` handles `SIGTERM` (`bpf_tc_detach`) plus a `preStop`
hook that removes the leftover `clsact` qdisc.

## Prerequisites

On each node (including nodes you will add later):

- Linux kernel with TC-BPF + `bpf_skb_ct_*` kfuncs support, bpffs mountable at `/sys/fs/bpf`.
- kubelet able to run privileged DaemonSet Pods (`hostNetwork`, `/lib/modules`, `/sys/fs/bpf`).

On the control-plane where you install from:

- `kubectl` pointed at the cluster (admin kubeconfig).
- `docker` (only if you rebuild images) + access to push to your registry.

## Install (run once from control-plane)

### Option A: one-shot script (recommended)

```bash
./kube/build-and-install.sh
```

This builds both images, pushes them, applies RBAC + DaemonSet, and waits for rollout.
Custom registry:

```bash
REGISTRY=myregistry.example.com/team ./kube/build-and-install.sh
# Build locally without pushing (images must already be visible to nodes):
SKIP_PUSH=1 ./kube/build-and-install.sh
```

Expected image variables (defaults shown):

```bash
REGISTRY=fchrgrib
TRACKER_IMG=$REGISTRY/pod-ip-tracker:latest
LOADER_IMG=$REGISTRY/tc-lb-loader:latest
```

### Option B: local LAN, no Docker Hub (`192.168.122.0/24`)

Pulls stay on your gigabit LAN. Recommended: a LAN registry on the
control-plane (automatic pulls, including future nodes):

```bash
# 1. Once: start registry:2 on the control-plane (e.g. 192.168.122.100:5000)
sudo ./kube/setup-local-registry.sh
# 2. On EACH node, run the printed snippet (docker daemon.json OR containerd
#    hosts.toml for insecure registry), restart docker/containerd.
# 3. Build + push over LAN, DaemonSet is repointed automatically:
LOCAL_REGISTRY=192.168.122.100:5000 ./kube/build-and-install.sh
```

Zero-registry fallback (no daemon changes, but manual per new node):

```bash
./kube/distribute-images.sh "192.168.122.101 192.168.122.102"  # scp + ctr import
SKIP_BUILD=1 REGISTRY=local ./kube/build-and-install.sh        # uses preloaded images
# New nodes joining later need distribute-images.sh re-run with their IP.
```

### Option B: manual steps (same as script)

```bash
# 1. Build + push (run where docker works; Dockerfile contexts matter)
docker build -f go/pods_watcher/Dockerfile -t fchrgrib/pod-ip-tracker:latest go/pods_watcher
docker build -f bpf/tc/Dockerfile -t fchrgrib/tc-lb-loader:latest .
docker push fchrgrib/pod-ip-tracker:latest
docker push fchrgrib/tc-lb-loader:latest

# 2. Install from control-plane (only this step needs the cluster)
kubectl apply -f kube/service/pt_rbac.yaml
kubectl apply -f kube/service/pt_daemonset.yaml
kubectl rollout status daemonset/pod-ip-tracker --timeout=180s

# 3. Demo backend + service (optional)
kubectl apply -f kube/service/backend.yaml
kubectl apply -f kube/service/lb_service.yaml
```

### Adding / removing nodes

No LB-specific step. Just join / remove the node the normal way (`kubeadm join`,
cluster autoscaler, cloud provider, etc.):

- New `Ready` node → DaemonSet creates a `pod-ip-tracker-*` Pod on it within seconds.
- Deleted/drained node → Pod is deleted; `SIGTERM` + `preStop` detaches TC and deletes `clsact`.

Verify:

```bash
kubectl get pods -o wide -l app=pod-ip-tracker
kubectl get ds pod-ip-tracker
```

## Configuration

No rebuild needed to switch Service / NodePort — everything is env-driven.
`LB_NODEPORT` accepts any `1-65535`; backend IPs are optional (`auto` =
dynamic-only from the tracker map).

| Container | Env | Default | Meaning |
|---|---|---|---|
| `tracker` | `LB_SERVICE_NAME` | `test-service` | Which Service to balance. Any selector keys work (not just `app=`). |
| `tracker` | `LB_NAMESPACE` | `default` | Namespace of that Service. |
| `tc-loader` | `LB_NODEPORT` | `30080` | Must equal your Service's `nodePort`. Old `svc_map` entries for other ports are deleted on startup. |
| `tc-loader` | `LB_TARGET_PORT` | `8000` | Must equal backend `containerPort` / Service `targetPort`. Used in DNAT. |
| `tc-loader` | `LB_IFACE` | `""` (auto) | Host iface. Empty = `ip route get 1.1.1.1` → `dev`, fallback first non-`lo`. Set explicitly (e.g. `ens3`) on multi-NIC nodes. |
| `tc-loader` | `LB_BE1` / `LB_BE2` | `auto` | Optional static fallbacks for `svc_map`. Live IPs come from the tracker map. |

### Use your own Service / NodePort

```bash
# At install time:
SERVICE_NAME=my-api NAMESPACE=prod NODEPORT=31001 TARGET_PORT=8080 ./kube/build-and-install.sh

# Or switch an existing install (restarts DaemonSet Pods, ~seconds):
kubectl set env ds/pod-ip-tracker -c tracker LB_SERVICE_NAME=my-api LB_NAMESPACE=prod
kubectl set env ds/pod-ip-tracker -c tc-loader LB_NODEPORT=31001 LB_TARGET_PORT=8080
kubectl rollout status ds/pod-ip-tracker
```

Requirements for your Service: type `NodePort` (or any Service with a `nodePort`
number), plus a non-empty `.spec.selector` so the tracker can find its Pods.
Example:

```yaml
apiVersion: v1
kind: Service
metadata: { name: my-api, namespace: prod }
spec:
  type: NodePort
  selector: { app: my-api }
  ports:
  - port: 80
    targetPort: 8080
    nodePort: 31001   # <- set LB_NODEPORT to this
```

## Verify it works

```bash
# 1 Pod per node, both containers Running
kubectl get pods -o wide -l app=pod-ip-tracker

# Tracker is syncing pod IPs
kubectl logs -l app=pod-ip-tracker -c tracker --tail=20
# expect: "Updated eBPF map with 3 pod IPs for service test-service"

# TC program attached on the node (run on the node itself)
tc filter show dev $(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}') ingress
ls -l /sys/fs/bpf/service_pod_ips /sys/fs/bpf/selected

# Traffic test (NodePort from outside or localhost on node)
curl http://<any-node-ip>:30080/
```

## Uninstall

```bash
kubectl delete -f kube/service/pt_daemonset.yaml
kubectl delete -f kube/service/backend.yaml
kubectl delete -f kube/service/lb_service.yaml
kubectl delete -f kube/service/pt_rbac.yaml
```

Pod deletion triggers `SIGTERM` → `bpf_tc_detach`, then `preStop` deletes the
`clsact` qdisc. If a node died hard and the qdisc is left behind, clean it manually
on that node:

```bash
tc qdisc del dev <iface> clsact
rm -f /sys/fs/bpf/service_pod_ips /sys/fs/bpf/selected /sys/fs/bpf/hash_map
```

## Troubleshooting

- **New node has no LB Pod**: `kubectl describe ds pod-ip-tracker`; check node taints
  (DaemonSet tolerates `Exists`, so it should match) and image pull errors
  (`kubectl get events --all-namespaces`).
- **`tracker` CrashLoop / RBAC errors**: `kubectl logs -l app=pod-ip-tracker -c tracker`;
  the binary uses in-cluster config — no `KUBECONFIG` needed inside the Pod.
  Local `go run` falls back to `$KUBECONFIG` or `~/.kube/config`.
- **`tc-loader` CrashLoop**: `kubectl logs -l app=pod-ip-tracker -c tc-loader`;
  usually wrong `LB_IFACE` or `LB_NODEPORT` out of `30000-32000` range.
- **Stale `clsact` after force-deleted Pod**: run the manual cleanup above.

## Project layout

```text
bpf/tc/            tc.bpf.c (datapath), tc.c (loader/least-conn loop), Dockerfile, entrypoint.sh
bpf/fentry/        fentry tracing for map sync
go/pods_watcher/   tracker daemon (Pod watch → pinned eBPF map), Dockerfile
go/map_sync/       cross-node hash_map sync via gRPC (optional, not in DaemonSet)
kube/service/      pt_rbac.yaml, pt_daemonset.yaml, lb_service.yaml, backend.yaml
kube/build-and-install.sh  one-shot build + control-plane install
```
