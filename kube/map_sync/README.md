# map_sync: secure cross-node map sync (mTLS + NetworkPolicy)

This hardens the optional `map_sync` component. It keeps the same function
(sync `hash_map` connection counts between nodes) but removes the two biggest
risks: **unauthenticated/plaintext gRPC** and **runnning on the host network**.

## Security model

```
scope reduction  : map_sync runs on the POD network, not hostNetwork
network policy   : only map_sync pods may reach :50051
mTLS             : cert-manager issues a CA + workload cert; peers verify each other
least privilege  : no privileged, no hostPID, drops ALL caps, adds BPF/PERFMON/SYS_RESOURCE
```

Only the datapath (`tracker`, `tc-loader`) stays privileged. The control plane
(`map_sync`) is now an ordinary, locked-down workload.

## Prerequisites

1. `kubectl` with admin access, `docker` for building the image.
2. A CNI that **enforces NetworkPolicy** (Calico/Cilium). Check:
   ```bash
   kubectl get pods -A | grep -E 'calico|cilium'
   ```
   If you use flannel, the NetworkPolicy is ignored (mTLS still protects you).
3. **cert-manager** installed:
   ```bash
   kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.15.3/cert-manager.yaml
   kubectl -n cert-manager wait --for=condition=Available deploy --all --timeout=180s
   ```

## Install (one command)

On the control-plane:

```bash
./kube/map_sync/install.sh

# LAN registry, no Docker Hub:
REGISTRY=192.168.122.100:5000 ./kube/map_sync/install.sh

# Images preloaded on nodes (no push):
SKIP_PUSH=1 REGISTRY=local MAP_SYNC_IMG=local/map-sync:latest ./kube/map_sync/install.sh
```

What it does, in order:

1. Verifies cert-manager is installed.
2. Builds/pushes the `map-sync` image (`go/map_sync/Dockerfile`).
3. Applies the self-signed bootstrap issuer, the CA cert, and the CA `ClusterIssuer`.
4. Applies `ServiceAccount`, headless `Service`, workload `Certificate`, `NetworkPolicy`.
5. Applies the `DaemonSet` (image substituted).
6. Waits for rollout.

## Step-by-step (if you prefer manual)

```bash
# 1. Build + push the image
docker build -f go/map_sync/Dockerfile -t fchrgrib/map-sync:latest .
docker push fchrgrib/map-sync:latest

# 2. Create the CA (once per cluster)
kubectl apply -f kube/map_sync/cert-manager.yaml
kubectl -n cert-manager wait --for=condition=Ready certificate/map-sync-ca --timeout=180s

# 3. Create workload identity + networking
kubectl apply -f kube/map_sync/rbac.yaml
kubectl apply -f kube/map_sync/service.yaml
kubectl apply -f kube/map_sync/certificate.yaml
kubectl apply -f kube/map_sync/networkpolicy.yaml
kubectl wait --for=condition=Ready certificate/map-sync-tls --timeout=180s

# 4. Deploy
sed 's|__IMAGE__|fchrgrib/map-sync:latest|g' kube/map_sync/daemonset.yaml | kubectl apply -f -
kubectl rollout status ds/map-sync --timeout=180s
```

## Verify

```bash
# Pods: 1 per node, Running
kubectl get pods -o wide -l app=map-sync

# Cert was issued and stored as a Secret
kubectl get certificate
kubectl get secret map-sync-tls

# Logs show TLS + peer discovery, no plaintext warning
kubectl logs -l app=map-sync --tail=30

# NetworkPolicy is active
kubectl get networkpolicy map-sync
```

Expected log lines (no `WARNING: TLS disabled`):

```
Server is running at :50051
```

## How mTLS works here

- cert-manager issues **one cert** bound to the headless service DNS name
  (`map-sync.default.svc.cluster.local`, plus `map-sync.default.svc` etc.).
- Every pod shares that cert and the `ca.crt`.
- The **server** requires and verifies client certs (`RequireAndVerifyClientCert`).
- The **client** dials a pod IP but sets `ServerName` to the service DNS, so
  verification succeeds no matter which pod IP replies.
- Cert rotates automatically (`duration: 90d`, `renewBefore: 30d`), and
  `rotationPolicy: Always` mints a new key each renewal.

This means an attacker on the LAN (or another pod) cannot talk to `:50051`
without a cert signed by your CA — and NetworkPolicy blocks them at L3 anyway.

## Peer discovery

`-peer-dns=map-sync.default.svc.cluster.local` resolves to every map_sync pod IP
via the headless Service. Each pod excludes its own `POD_IP` and syncs to the
rest. No more hardcoded node IPs. Legacy `-ip <host>` still works if you pass it.

## Configuration

All via `args:` in `kube/map_sync/daemonset.yaml`:

| Flag | Default | Meaning |
|---|---|---|
| `-port` | `50051` | gRPC listen port |
| `-peer-dns` | `""` | Headless service DNS for peer discovery (preferred) |
| `-ip` | `""` | Legacy single peer to sync to |
| `-pod-ip` | `$POD_IP` | This pod's IP, excluded from peers |
| `-tls-cert` / `-tls-key` | `""` | TLS keypair (empty = plaintext, warns) |
| `-tls-ca` | `""` | CA bundle; enables mutual TLS |
| `-tls-server-name` | `""` | Expected cert SAN when dialing peers |

## Uninstall

```bash
kubectl delete -f kube/map_sync/daemonset.yaml
kubectl delete -f kube/map_sync/networkpolicy.yaml
kubectl delete -f kube/map_sync/service.yaml
kubectl delete -f kube/map_sync/certificate.yaml
kubectl delete -f kube/map_sync/rbac.yaml
kubectl delete -f kube/map_sync/cert-manager.yaml   # remove CA + issuer
```

## Troubleshooting

- **Pod `CreateContainerConfigError` / TLS file missing** → the `map-sync-tls`
  Secret isn't ready yet. Check `kubectl describe certificate map-sync-tls`.
- **`permission denied` loading fentry** → kernel < 5.8 without `CAP_BPF`.
  Add `SYS_ADMIN` to the capability list (and accept the broader grant).
- **Peers not found** → check the Service has endpoints:
  `kubectl get endpoints map-sync`; `publishNotReadyAddresses: true` should list pods.
- **`certificate not signed by CA`** → client `-tls-server-name` must match a SAN
  in `certificate.yaml` (`map-sync.default.svc.cluster.local`).
- **NetworkPolicy has no effect** → your CNI doesn't enforce it (flannel). mTLS
  still applies; for L3 control add a node firewall rule instead.
