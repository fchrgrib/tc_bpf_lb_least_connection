#!/bin/bash
# Preflight + verification for the TC eBPF load balancer.
# Run on the control-plane (needs kubectl access). Read-only: changes nothing.
#
#   ./kube/verify.sh
#   NAMESPACE=prod SERVICE_NAME=my-api NODEPORT=31001 ./kube/verify.sh
set -uo pipefail

NS="${NAMESPACE:-default}"
SVC="${SERVICE_NAME:-test-service}"
NODEPORT="${NODEPORT:-30080}"
TARGET_PORT="${TARGET_PORT:-8000}"
DS="pod-ip-tracker"

OK=0; WARN=0; FAIL=0
ok()   { echo "  [ OK ] $*"; OK=$((OK+1)); }
warn() { echo "  [WARN] $*"; WARN=$((WARN+1)); }
fail() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }
hdr()  { echo; echo "=== $* ==="; }

# Compare kernel version major.minor against a minimum.
kver_ge() {
  local have="$1" want="$2"
  local hM hm wM wm
  hM=$(echo "$have" | cut -d. -f1); hm=$(echo "$have" | cut -d. -f2)
  wM=$(echo "$want" | cut -d. -f1); wm=$(echo "$want" | cut -d. -f2)
  [ "$hM" -gt "$wM" ] || { [ "$hM" -eq "$wM" ] && [ "$hm" -ge "$wm" ]; }
}

hdr "1. kubectl connectivity"
if kubectl version >/dev/null 2>&1; then
  ok "kubectl can reach the API server ($(kubectl config current-context 2>/dev/null))"
else
  fail "kubectl cannot reach the API server — run this on the control-plane"
  echo; echo "Cannot continue without cluster access."; exit 1
fi

hdr "2. Nodes (kernel >= 5.8 for CAP_BPF; >= 5.5 minimum for TC-BPF)"
NODES=$(kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.name}{" "}{.status.nodeInfo.kernelVersion}{" "}{.status.conditions[?(@.type=="Ready")].status}{"\n"}{end}')
if [ -z "$NODES" ]; then
  fail "no nodes found"
else
  while read -r name kver ready; do
    [ -z "$name" ] && continue
    if [ "$ready" = "True" ]; then
      if kver_ge "$kver" "5.8"; then ok "$name  kernel=$kver  Ready"
      elif kver_ge "$kver" "5.5"; then warn "$name  kernel=$kver  Ready (no CAP_BPF: add SYS_ADMIN to containers)"
      else fail "$name  kernel=$kver  TOO OLD (need >=5.5 for TC-BPF)"
      fi
    else
      fail "$name  kernel=$kver  NOT Ready"
    fi
  done <<< "$NODES"
fi

hdr "3. DaemonSet status"
if kubectl -n "$NS" get ds "$DS" >/dev/null 2>&1; then
  DESIRED=$(kubectl -n "$NS" get ds "$DS" -o jsonpath='{.status.desiredNumberScheduled}')
  READY=$(kubectl -n "$NS" get ds "$DS" -o jsonpath='{.status.numberReady}')
  AVAIL=$(kubectl -n "$NS" get ds "$DS" -o jsonpath='{.status.numberAvailable}')
  echo "  desired=$DESIRED ready=$READY available=$AVAIL"
  if [ "${READY:-0}" -eq "${DESIRED:-0}" ] && [ "${DESIRED:-0}" -gt 0 ]; then
    ok "all $DESIRED node(s) have a running LB pod"
  else
    fail "only ${READY:-0}/${DESIRED:-0} pods ready"
  fi
else
  fail "DaemonSet $DS not found in namespace $NS (install it: ./kube/build-and-install.sh)"
fi

hdr "4. Pods, containers, restarts"
kubectl -n "$NS" get pods -o wide -l app="$DS" 2>/dev/null || warn "no pods listed"

hdr "4b. active-conn (tracepoint) — required for counts to DECREMENT"
if kubectl -n "$NS" get ds active-conn >/dev/null 2>&1; then
  AC_READY=$(kubectl -n "$NS" get ds active-conn -o jsonpath='{.status.numberReady}')
  AC_DESIRED=$(kubectl -n "$NS" get ds active-conn -o jsonpath='{.status.desiredNumberScheduled}')
  if [ "${AC_READY:-0}" -eq "${AC_DESIRED:-0}" ] && [ "${AC_DESIRED:-0}" -gt 0 ]; then
    ok "active-conn running on $AC_READY/$AC_DESIRED node(s)"
  else
    fail "active-conn only ${AC_READY:-0}/${AC_DESIRED:-0} ready"
  fi
  if kubectl -n "$NS" logs -l app=active-conn --tail=5 2>/dev/null | grep -q "attached tracepoint"; then
    ok "tracepoint sock/inet_sock_set_state attached"
  else
    warn "no 'attached tracepoint' log line (check: kubectl logs -l app=active-conn)"
  fi
else
  fail "DaemonSet active-conn NOT installed — hash_map will only ever INCREASE,
        so 'least connection' degrades to 'fewest connections ever seen'.
        Install with: ONLY=active-conn ./kube/build-and-install.sh"
fi

hdr "5. Recent warning events in $NS"
EV=$(kubectl -n "$NS" get events --field-selector type=Warning \
      --sort-by='.lastTimestamp' 2>/dev/null | tail -12)
if [ -n "$EV" ]; then echo "$EV"; warn "review the warnings above (image pull / scheduling / capability)"; else ok "no warning events"; fi

hdr "6. Service / NodePort wiring"
if kubectl -n "$NS" get svc "$SVC" >/dev/null 2>&1; then
  SNP=$(kubectl -n "$NS" get svc "$SVC" -o jsonpath='{.spec.ports[0].nodePort}')
  STP=$(kubectl -n "$NS" get svc "$SVC" -o jsonpath='{.spec.ports[0].targetPort}')
  SEL=$(kubectl -n "$NS" get svc "$SVC" -o jsonpath='{.spec.selector}')
  ok "Service $NS/$SVC nodePort=$SNP targetPort=$STP selector=$SEL"
  [ -n "$SNP" ] && [ "$SNP" != "0" ] && ok "nodePort is set ($SNP)" || fail "Service has no nodePort"
  [ -n "$STP" ] && [ "$STP" != "0" ] && ok "numeric targetPort ($STP)" || warn "targetPort is named/empty; tracker falls back to spec.port"
  EPS=$(kubectl -n "$NS" get endpoints "$SVC" -o jsonpath='{.subsets[*].addresses[*].ip}' 2>/dev/null)
  [ -n "$EPS" ] && ok "backend endpoints exist: $EPS" || fail "no backend endpoints — service selector matches no ready pods"
else
  fail "Service $NS/$SVC not found"
fi

hdr "7. Node-level checks (via a running tc-loader pod)"
POD=$(kubectl -n "$NS" get pods -l app="$DS" -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
if [ -z "$POD" ]; then
  warn "no LB pod to exec into — skipping node checks"
else
  NODE=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.spec.nodeName}')
  echo "  exec target: $POD (node $NODE)"
  EX="kubectl -n $NS exec $POD -c tc-loader --"

  # BTF (CO-RE) presence
  if $EX sh -c 'test -f /sys/kernel/btf/vmlinux' >/dev/null 2>&1; then
    ok "BTF present at /sys/kernel/btf/vmlinux (CO-RE works)"
  else
    warn "no BTF at /sys/kernel/btf/vmlinux (kernel built without CONFIG_DEBUG_INFO_BTF?)"
  fi

  # default route iface
  IFACE=$($EX sh -c "ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if(\$i==\"dev\") print \$(i+1)}' | head -n1" 2>/dev/null)
  [ -n "$IFACE" ] && ok "default-route iface on node: $IFACE" || fail "no default route found on node"

  # TC program attached
  if [ -n "$IFACE" ]; then
    if $EX tc filter show dev "$IFACE" ingress >/dev/null 2>&1; then
      ATTACH=$($EX sh -c "tc filter show dev $IFACE ingress 2>/dev/null | grep -c bpf")
      [ "${ATTACH:-0}" -gt 0 ] && ok "TC bpf filter attached on $IFACE ingress" || warn "no bpf filter on $IFACE (tc-loader may not be ready yet)"
    else
      warn "could not run 'tc filter show' (tc-loader restarting?)"
    fi
  fi

  # pinned maps
  MAPS=$($EX sh -c 'ls /sys/fs/bpf 2>/dev/null | tr "\n" " "' 2>/dev/null)
  echo "  /sys/fs/bpf: ${MAPS:-<empty>}"
  for m in svc_map backends svc_ports hash_map remote_counts; do
    echo "$MAPS" | grep -q "$m" && ok "pinned map: $m" || warn "pinned map missing: $m"
  done
fi

hdr "8. Controller logs (last 15 lines)"
echo "--- tracker ---"
kubectl -n "$NS" logs -l app="$DS" -c tracker --tail=15 --prefix 2>/dev/null \
  || warn "no tracker logs (container not started?)"
echo "--- tc-loader ---"
kubectl -n "$NS" logs -l app="$DS" -c tc-loader --tail=15 --prefix 2>/dev/null \
  || warn "no tc-loader logs (container not started?)"

hdr "9. Traffic test"
NODE_IP=$(kubectl get nodes -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}' 2>/dev/null)
if [ -n "$NODE_IP" ]; then
  echo "  try: curl -sS --max-time 5 http://$NODE_IP:$NODEPORT/   (from outside, or on the node)"
  warn "manual step: run the curl above to confirm end-to-end"
fi

echo
echo "================ SUMMARY ================"
echo "  OK=$OK  WARN=$WARN  FAIL=$FAIL"
if [ "$FAIL" -eq 0 ] && [ "$WARN" -eq 0 ]; then
  echo "  VERDICT: healthy — LB should be serving."
elif [ "$FAIL" -eq 0 ]; then
  echo "  VERDICT: functional, but review the WARN lines above."
else
  echo "  VERDICT: NOT fully working — fix FAIL lines above."
fi
exit 0
