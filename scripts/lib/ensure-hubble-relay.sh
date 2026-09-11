#!/usr/bin/env bash
# Ensure Cilium Hubble Relay is available (required for Netra live flows).
# Safe to run repeatedly. Adapted from PacketWolf's ensure-hubble-relay.sh.
set -euo pipefail

export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"

kubectl_cmd() {
  local sys_k3s="/etc/rancher/k3s/k3s.yaml"
  if [[ -z "${KUBECONFIG:-}" || ! -r "${KUBECONFIG}" ]]; then
    if [[ -f "$sys_k3s" ]]; then
      if [[ -r "$sys_k3s" ]]; then
        export KUBECONFIG="$sys_k3s"
      else
        mkdir -p "$HOME/.kube"
        local kcfg="$HOME/.kube/netra-k3s.yaml"
        sudo cat "$sys_k3s" > "$kcfg"
        chmod 600 "$kcfg"
        export KUBECONFIG="$kcfg"
      fi
    fi
  fi
  if command -v k3s >/dev/null 2>&1 && [[ ! -x "$(command -v kubectl 2>/dev/null || true)" ]]; then
    k3s kubectl "$@"
    return $?
  fi
  kubectl "$@"
}

hubble_relay_ready() {
  kubectl_cmd get deploy -n kube-system hubble-relay &>/dev/null \
    && kubectl_cmd -n kube-system wait --for=condition=available deploy/hubble-relay --timeout=5s &>/dev/null
}

if hubble_relay_ready; then
  echo "Hubble Relay already available"
  exit 0
fi

if ! kubectl_cmd get daemonset -n kube-system cilium &>/dev/null; then
  echo "Cilium DaemonSet not found; install Cilium before Netra" >&2
  exit 1
fi

if command -v cilium >/dev/null 2>&1; then
  echo "Enabling Hubble Relay via cilium CLI..."
  cilium hubble enable --relay || true
fi

if ! hubble_relay_ready && command -v helm >/dev/null 2>&1; then
  echo "Enabling Hubble Relay via Helm upgrade..."
  helm repo add cilium https://helm.cilium.io/ 2>/dev/null || true
  helm repo update cilium 2>/dev/null || true
  chart_version="$(helm list -n kube-system -o json 2>/dev/null | python3 -c 'import json,sys
try:
  rels=json.load(sys.stdin)
except Exception:
  sys.exit(1)
for r in rels:
  if r.get("name")=="cilium":
    print(r["chart"].split("-")[-1]); sys.exit(0)
sys.exit(1)' 2>/dev/null || echo 1.20.0)"
  helm upgrade cilium cilium/cilium --version "$chart_version" --namespace kube-system \
    --reuse-values \
    --set hubble.enabled=true \
    --set hubble.relay.enabled=true \
    --wait --timeout 300s
fi

kubectl_cmd -n kube-system wait --for=condition=available deploy/hubble-relay --timeout=180s
echo "Hubble Relay ready"
