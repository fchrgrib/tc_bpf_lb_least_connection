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

1. `tracker` (`bpf/user_space/pods_watcher`) watches the Services you opt in
   through the K8s API and keeps each one's ready backends in pinned eBPF maps
   (`/sys/fs/bpf/svc_map` + `/sys/fs/bpf/backends`), always current as Pods scale.
2. The TC program (`bpf/data_plane/tc`) attaches at **ingress** on each node's
   physical iface. For a new TCP/UDP flow to a balanced `nodePort`, it picks a
   backend itself (power-of-two choices on the live counts) and DNATs the packet
   (plus SNAT/masquerade) using kernel conntrack (`bpf_skb_ct_*`), so return
   traffic works with no userspace hop.
3. `active-conn` (`bpf/user_space/trace`) counts active connections per pod IP
   from a tracepoint, and `map_sync` (`bpf/user_space/map_sync`) snapshots those
   per-node counts to peers, so every node sees a cluster-wide load view.

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
  manifest works for any Service via env (`LB_NAMESPACE`,
  `LB_SERVICE_SELECTOR` or `LB_SERVICE_NAME`).
- **Cheap to try per Service.** Point it at one `NodePort` Service first
  (e.g. the heaviest long-connection API), leave the rest on kube-proxy.

- **Cheap to try per Service.** Point it at one `NodePort` Service first
  (e.g. the heaviest long-connection API), leave the rest on kube-proxy.

## Limitations (please read before production use)

- **Up to 64 Services per install.** `MAX_SERVICES` slots, each with up to
  `MAX_BACKENDS` (256) backends. Beyond that the tracker logs and skips; raise
  the constants (and re-pin the maps) for more.
- **NodePort Services only.** No `ClusterIP`-only or `LoadBalancer` support;
  the Service must have a numeric `nodePort` and `targetPort`.
- **IPv4 TCP/UDP only.** The datapath (`tc.bpf.c`) parses `ETH_P_IP` + TCP/UDP
  tuples; other protocols pass through untouched, IPv6 is not NATed.
- **Kernel requirement.** Needs TC-BPF with `clsact` plus `bpf_skb_ct_*`
  conntrack kfuncs (recent kernels, e.g. 6.x with `CONFIG_NETFILTER` conntrack).
  Old kernels fail at load/attach time.
- **Elevated per-node agent.** The datapath containers need `hostNetwork`, host
  mounts (`/lib/modules`, `/sys/fs/bpf`), and the `BPF`/`NET_ADMIN`/
  `SYS_RESOURCE` capabilities; the init container needs `SYS_ADMIN` to mount
  bpffs. It is **not** `privileged` and runs with `seccompProfile: Unconfined`
  (the default profile blocks `bpf()` without `CAP_SYS_ADMIN`). On kernels
  < 5.8 (no `CAP_BPF`) add `SYS_ADMIN` to the datapath containers.
- **Static fallback is 2 backends; scale cap ~100 Pods.** `svc_map` carries only
  `be1/be2` as fallback (live set comes from the tracker map, capped at 100
  entries in `ebpfMapSpec`), `hash_map` at 10240 entries. Tune `MaxEntries` for
  larger fleets.
- **Eventual consistency.** Backends follow EndpointSlices (ready-only) with a
  15s heartbeat reconcile; cross-node counts are snapshotted every 3s, so brief
  imbalance is possible right after scale/rollout events.
- **Counts lag.** The datapath samples the live maps, but counts are produced by
  a tracepoint and can be ~3s stale across nodes.
- **Per-node counts by default.** Without deploying `bpf/user_space/map_sync`
  (snapshot gRPC peer sync, installed by `--all`), each node balances on locally
  observed counts only.
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

- **Datapath in kernel (`bpf/data_plane/tc`, hook `tc_ingress`).** Every packet to
  a balanced `nodePort` is inspected before it climbs the normal stack. New flows
  get the least-connection pick + NAT via eBPF maps (`svc_map`, `backends`,
  `hash_map`, `remote_counts`); established flows hit existing conntrack entries
  and pass through. No per-packet trip to userspace.
- **Control plane in userspace.** K8s watch (`tracker`) and cross-node count
  sync (`map_sync` periodic snapshots + gRPC) just read/write those same maps.
  Kernel and userspace share state through maps, not syscalls per packet.

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

Four components run on **every node**. Two live in one DaemonSet
(`kube/service/pt_daemonset.yaml`, name `pod-ip-tracker`); two are separate
DaemonSets with tighter privileges:

| Component | Source | Job |
|---|---|---|
| `tracker` | `bpf/user_space/pods_watcher` | Watches opted-in Services + EndpointSlices; writes `/sys/fs/bpf/svc_map`, `/sys/fs/bpf/backends`, `/sys/fs/bpf/svc_ports` |
| `tc-loader` | `bpf/user_space/tc` | Attaches the TC program (`bpf/data_plane/tc`) to the host iface. No routing logic and no timers |
| `active-conn` | `bpf/user_space/trace` + `bpf/data_plane/trace` | **Counts active server-side connections per pod IP** — `+1` ESTABLISHED, `-1` CLOSE, scoped to balanced target ports (`hash_map`) |
| `map-sync` | `bpf/user_space/map_sync` | Periodically snapshots the local `hash_map` to peers and writes their sum into `remote_counts` (mTLS gRPC) |

The chain that makes least-connection correct:

```
active-conn   hash_map[podIP]        (+1 establish / -1 close, port-scoped)
     ↓ map-sync snapshot (every 3s, mTLS gRPC)
map-sync      remote_counts[podIP]   (sum of peers' counts)
     ↓
tc datapath   per NEW flow: P2C over (hash_map + remote_counts) → DNAT
```

> **`active-conn` is not optional.** Without it the counts stay at zero, so the
> datapath falls back to a random choice among healthy backends. Install it with
> `./kube/build-and-install.sh --all` (or `ONLY=active-conn ./kube/build-and-install.sh`).

Supporting pieces:

- `kube/service/pt_rbac.yaml` — ServiceAccount + namespace-scoped `Role`/`RoleBinding` (`get,list,watch` on `services,endpointslices`).
- `kube/service/lb_service.yaml` — demo `NodePort` Service (`nodePort: 30080`, `targetPort: 8000`).
- `kube/service/backend.yaml` — demo backend Deployment (3x `flask-backend` on port 8000).
- `bpf/user_space/tc` — auto-detects the host iface per node (see Configuration).
- `kube/build-and-install.sh` — one-shot build + install for **all** components (`--all`, or `ONLY=<comp>`).
- `kube/verify.sh` — read-only preflight + health check.

Auto-scale behavior is native Kubernetes: the DaemonSet controller creates one Pod
per matching node on join (`Ready`) and garbage-collects the Pod on node
delete/drain. The `tc-loader` handles `SIGTERM` (`bpf_tc_detach`) plus a `preStop`
hook that removes the leftover `clsact` qdisc.

## Prerequisites

First, fetch the vendored dependencies (libbpf, bpftool, vmlinux.h, blazesym
live in `lib/` as git submodules, so a fresh clone needs them initialized):

```bash
git submodule update --init --recursive
```

On each node (including nodes you will add later):

- Linux kernel with TC-BPF + `bpf_skb_ct_*` kfuncs support, bpffs mountable at `/sys/fs/bpf`.
- kubelet able to run DaemonSet Pods with `hostNetwork` and the host mounts
  `/lib/modules`, `/sys/fs/bpf` (no `privileged` required).

On the control-plane where you install from:

- `kubectl` pointed at the cluster (admin kubeconfig).
- `docker` (only if you rebuild images) + access to push to your registry.

## Install (run once from control-plane)

### Option A: one-shot script (recommended)

```bash
# Base LB only (tracker + tc-loader):
./kube/build-and-install.sh

# Everything in one command (base LB + active-conn + map_sync):
./kube/build-and-install.sh --all
```

This builds all images, pushes them, applies RBAC + DaemonSets, and waits for rollout.
Custom registry:

```bash
REGISTRY=myregistry.example.com/team ./kube/build-and-install.sh --all
# Build locally without pushing (images must already be visible to nodes):
SKIP_PUSH=1 ./kube/build-and-install.sh --all
```

Expected image variables (defaults shown):

```bash
REGISTRY=fchrgrib
TRACKER_IMG=$REGISTRY/pod-ip-tracker:latest
LOADER_IMG=$REGISTRY/tc-lb-loader:latest
ACTIVE_CONN_IMG=$REGISTRY/active-conn:latest
MAP_SYNC_IMG=$REGISTRY/map-sync:latest
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
LOCAL_REGISTRY=192.168.122.100:5000 ./kube/build-and-install.sh --all
```

Zero-registry fallback (no daemon changes, but manual per new node):

```bash
./kube/distribute-images.sh "192.168.122.101 192.168.122.102"  # scp + ctr import
SKIP_BUILD=1 REGISTRY=local ./kube/build-and-install.sh --all  # uses preloaded images
# New nodes joining later need distribute-images.sh re-run with their IP.
```

### Option C: manual steps (same as script)

```bash
# 1. Build + push (run where docker works; Dockerfile contexts matter)
docker build -f bpf/user_space/pods_watcher/Dockerfile -t fchrgrib/pod-ip-tracker:latest bpf/user_space
docker build -f bpf/user_space/tc/Dockerfile -t fchrgrib/tc-lb-loader:latest .
docker build -f bpf/user_space/trace/Dockerfile -t fchrgrib/active-conn:latest .
docker build -f bpf/user_space/map_sync/Dockerfile -t fchrgrib/map-sync:latest .

# 2. Install from control-plane (only this step needs the cluster)
kubectl apply -f kube/service/pt_rbac.yaml
kubectl apply -f kube/service/pt_daemonset.yaml
kubectl rollout status daemonset/pod-ip-tracker --timeout=180s

# 3. Active-conn (tracepoint)
kubectl apply -f kube/active_conn/rbac.yaml
sed 's|__IMAGE__|fchrgrib/active-conn:latest|g' kube/active_conn/daemonset.yaml | kubectl apply -f -
kubectl rollout status ds/active-conn --timeout=180s

# 4. Map-sync (requires cert-manager)
kubectl apply -f kube/map_sync/cert-manager.yaml
kubectl -n cert-manager wait --for=condition=Ready certificate/map-sync-ca --timeout=180s
kubectl apply -f kube/map_sync/rbac.yaml kube/map_sync/service.yaml kube/map_sync/certificate.yaml kube/map_sync/networkpolicy.yaml
kubectl -n default wait --for=condition=Ready certificate/map-sync-tls --timeout=180s
sed 's|__IMAGE__|fchrgrib/map-sync:latest|g' kube/map_sync/daemonset.yaml | kubectl apply -f -
kubectl rollout status ds/map-sync --timeout=180s

# 5. Demo backend + service (optional)
kubectl apply -f kube/service/backend.yaml
kubectl apply -f kube/service/lb_service.yaml
```

### Installing the full least-connection chain (tracker + tc-loader + map_sync + active-conn)

```bash
# One command installs everything:
./kube/build-and-install.sh --all

# Or target a single component (builds + installs just that one):
ONLY=active-conn ./kube/build-and-install.sh   # active connection counter
ONLY=map-sync    ./kube/build-and-install.sh   # cross-node map sync
```

After installation, the full chain is:
```
active-conn   +1 ESTABLISHED / -1 CLOSE  hash_map[podIP]  (port-scoped)
     ↓ map-sync snapshot (mTLS gRPC)
map-sync      remote_counts[podIP]       (peers' counts)
     ↓
tc datapath   per new flow: P2C over hash_map + remote_counts → DNAT
```

### Adding / removing nodes

## Configuration

No rebuild needed to add or switch Services — the tracker reads the cluster and
writes maps; the datapath makes decisions per new flow.

| Container | Env / Flag | Default | Meaning |
|---|---|---|---|
| `tracker` | `LB_NAMESPACE` | `default` | Namespace to watch. |
| `tracker` | `LB_SERVICE_SELECTOR` | `""` | Balance every Service matching this label selector. |
| `tracker` | `LB_SERVICE_NAME` | `""` | Otherwise, balance exactly this one Service. Both empty = every NodePort Service in the namespace. |
| `tc-loader` | `LB_IFACE` | `""` (auto) | Host iface. Empty = default route, else first non-`lo`. |
| `map-sync` | `-interval` | `3s` | Snapshot publish period. |
| `map-sync` | `-peer-ttl` | `15s` | Drop a silent peer's counts after this. |
| `map-sync` | `-peer-dns` / `-ip` / `-pod-ip` / `-port` | | Peer discovery / identity. |
| `map-sync` | `-tls-cert` / `-tls-key` / `-tls-ca` / `-tls-server-name` | | mTLS credentials. |

### Add a Service

Create a `NodePort` Service with a numeric `targetPort`, then register it once:

```bash
# Option A: label it (paired with LB_SERVICE_SELECTOR on the tracker)
kubectl label svc/my-api -n prod lb.example.com/enabled=true

# Option B: pin it by name (LB_SERVICE_NAME=my-api)
```

The tracker picks it up on the next watch event / 15s heartbeat — **no redeploy**.
Remove the label (or delete the Service) to stop balancing it; existing
connections drain.

```yaml
apiVersion: v1
kind: Service
metadata:
  name: my-api
  namespace: prod
  labels: { lb.example.com/enabled: "true" }
spec:
  type: NodePort
  selector: { app: my-api }
  ports:
  - port: 80
    targetPort: 8080
    nodePort: 31001
```

## Verify it works

Automated preflight + health check (run on the control-plane; read-only):

```bash
./kube/verify.sh
# NAMESPACE=prod SERVICE_NAME=my-api NODEPORT=31001 ./kube/verify.sh
```

It checks kernel/BTF requirements, DaemonSet readiness, events, Service/NodePort
wiring, pinned maps, the attached TC filter, and prints logs — ending in a
`VERDICT` with an OK/WARN/FAIL summary.

Manual checks:

```bash
# 1 Pod per node, both containers Running
kubectl get pods -o wide -l app=pod-ip-tracker

# Tracker is syncing pod IPs
kubectl logs -l app=pod-ip-tracker -c tracker --tail=20
# expect: service default/test-service: nodePort 30080 -> 3 backend(s)

# TC program attached on the node (run on the node itself)
tc filter show dev $(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}') ingress
ls -l /sys/fs/bpf/svc_map /sys/fs/bpf/backends /sys/fs/bpf/hash_map /sys/fs/bpf/remote_counts

# Traffic test (NodePort from outside or localhost on node)
curl http://<any-node-ip>:30080/
```

## Metrics

Plain Prometheus text — no client library, just scrape the endpoint.

**`tracker`** on `:9101/metrics` (override with `METRICS_ADDR`):

| Metric | Type | Meaning |
|---|---|---|
| `lb_services` | gauge | Services currently balanced |
| `lb_balanced_ports` | gauge | Target ports counted by the tracepoint |
| `lb_backends{service,node_port}` | gauge | Ready backends per Service |
| `lb_backend_connections{service,backend_ip}` | gauge | Active connections per backend (local + remote) |
| `lb_flows_assigned_total{service}` | counter | New flows DNATed by the datapath |
| `lb_no_backend_total{service}` | counter | New flows with no healthy backend (fell back) |
| `lb_stale_fallback_total{service}` | counter | New flows skipped while the control plane was stale |

**`map-sync`** on `:9102/metrics` (`-metrics-addr`):

| Metric | Type | Meaning |
|---|---|---|
| `lb_sync_peers` | gauge | Peers contributing counts |
| `lb_sync_entries` | gauge | Pod IPs currently in `remote_counts` |
| `lb_sync_write_errors_total` | counter | Failed writes to `remote_counts` |
| `lb_sync_last_apply_age_seconds` | gauge | Age of the last applied peer snapshot |

`lb_backend_connections` is the distribution metric for evaluating the
algorithm: scrape it during a load test to see how evenly connections land.

## Uninstall

One command stops the LB (same selection flags as the installer):

```bash
./kube/uninstall.sh            # base LB (tracker + tc-loader)
./kube/uninstall.sh --all      # base LB + active-conn + map-sync
ONLY=map-sync ./kube/uninstall.sh
PURGE=1 ./kube/uninstall.sh --all   # also remove pinned eBPF maps on nodes
```

Pod deletion triggers `SIGTERM` → `bpf_tc_detach`, then `preStop` deletes the
`clsact` qdisc, so NodePort traffic immediately falls back to kube-proxy.
Reinstall any time with `./kube/build-and-install.sh --all`.

If a node died hard and the qdisc/maps are left behind, clean it manually on
that node:

```bash
tc qdisc del dev <iface> clsact
rm -f /sys/fs/bpf/svc_map /sys/fs/bpf/backends /sys/fs/bpf/svc_ports \
      /sys/fs/bpf/hash_map /sys/fs/bpf/remote_counts
```

## Security posture

Hardening is applied to both parts of the stack.

### Datapath (`tracker` + `tc-loader`)

The DaemonSet no longer uses `privileged` or `hostPID`. Each container gets only
the capabilities it needs, with `allowPrivilegeEscalation: false`,
`readOnlyRootFilesystem: true`, `seccompProfile: Unconfined`, and CPU/memory
limits:

| Container | Capabilities | Why |
|---|---|---|
| `tracker` | `BPF`, `SYS_RESOURCE` | open + write `svc_map`, `backends`, `svc_ports` |
| `tc-loader` | `BPF`, `NET_ADMIN`, `SYS_RESOURCE` | load program, attach TC, conntrack |
| `mount-bpf-fs` (init) | `SYS_ADMIN` | `mount(2)` bpffs only |

RBAC is a namespace-scoped `Role`/`RoleBinding` (not cluster-wide), and images
are pinned to `repo@sha256:<digest>` by `build-and-install.sh`. On kernels
**< 5.8** (no `CAP_BPF`) add `SYS_ADMIN` to the containers.

### Control plane (`map_sync`, optional)

A hardened, mTLS + NetworkPolicy deployment lives in `kube/map_sync/` — see
[`kube/map_sync/README.md`](kube/map_sync/README.md):

```bash
ONLY=map-sync ./kube/build-and-install.sh
```

It requires cert-manager, builds the `map-sync` image, stands up a CA + workload
cert, runs on the **pod network** (no `hostNetwork`) with
`BPF`/`PERFMON`/`SYS_RESOURCE` only, and restricts `:50051` to `map_sync` pods.

Principle: **only the datapath touches the host**; the control plane stays an
ordinary, locked-down workload.

## Troubleshooting

- **New node has no LB Pod**: `kubectl describe ds pod-ip-tracker`; check node taints
  (DaemonSet tolerates `Exists`, so it should match) and image pull errors
  (`kubectl get events --all-namespaces`).
- **`tracker` CrashLoop / RBAC errors**: `kubectl logs -l app=pod-ip-tracker -c tracker`;
  the binary uses in-cluster config — no `KUBECONFIG` needed inside the Pod.
  Local `go run` falls back to `$KUBECONFIG` or `~/.kube/config`.
- **`tc-loader` CrashLoop**: `kubectl logs -l app=pod-ip-tracker -c tc-loader`;
  usually a wrong `LB_IFACE` or the pinned maps couldn't be created (spec
  mismatch with a previously pinned map — delete `/sys/fs/bpf/svc_map` etc.).
- **Stale `clsact` after force-deleted Pod**: run the manual cleanup above.

## Project layout

```text
bpf/data_plane/tc/        tc.bpf.c (datapath - kernel space)
bpf/data_plane/trace/     tracepoint.bpf.c (kernel space)
bpf/user_space/tc/        tc.go (datapath attach + iface detection), Dockerfile
bpf/user_space/trace/     tracepoint.go (active-connection loader), Dockerfile
bpf/user_space/pods_watcher/ tracker daemon (Services → svc_map/backends), Dockerfile
bpf/user_space/map_sync/  snapshot-based cross-node count sync via gRPC, Dockerfile
lib/               submodules: libbpf, bpftool, vmlinux.h, blazesym
kube/service/      pt_rbac.yaml, pt_daemonset.yaml, lb_service.yaml, backend.yaml
kube/map_sync/     hardened map_sync: cert-manager mTLS, NetworkPolicy, DaemonSet
kube/active_conn/  active-conn: tracepoint DaemonSet, RBAC
kube/build-and-install.sh  one-shot build + install (--all, or ONLY=<comp>)
kube/uninstall.sh  one-shot stop + remove (--all, or ONLY=<comp>, PURGE=1)
kube/verify.sh     preflight + health check (read-only)
```
