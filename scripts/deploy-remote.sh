#!/usr/bin/env bash
# Netra — remote deploy (SSH + rsync + optional K3s/Cilium/Hubble + Helm)
#
# Profiles:
#   default / --k3s   Bootstrap K3s + Cilium 1.20 + Hubble Relay if needed, then Helm
#   --k8s             Helm on an existing kubeconfig (cluster already has Cilium)
#   --quick           Sync + Helm only (images must already exist on the host)
#
# Usage:
#   ./scripts/deploy-remote.sh user@10.0.1.5
#   ./scripts/deploy-remote.sh user@10.0.1.5 --k8s
#   ./scripts/deploy-container.sh user@10.0.1.5
#
# Netra runs on top of Cilium; it does not replace the CNI.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
# shellcheck source=scripts/lib/ensure-hubble-relay.sh
source "${SCRIPT_DIR}/lib/ensure-hubble-relay.sh"
# shellcheck source=scripts/lib/ensure-cilium-k3s.sh
source "${SCRIPT_DIR}/lib/ensure-cilium-k3s.sh"

PROFILE="k3s"
DRY_RUN=false
VERIFY_ONLY=false
TARGET=""
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30)

usage() {
  sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage ;;
    --k3s) PROFILE="k3s"; shift ;;
    --k8s) PROFILE="k8s"; shift ;;
    --quick) PROFILE="quick"; shift ;;
    --dry-run) DRY_RUN=true; shift ;;
    --verify-only) VERIFY_ONLY=true; shift ;;
    -*)
      echo "unknown flag: $1" >&2
      exit 2
      ;;
    *)
      TARGET="$1"
      shift
      ;;
  esac
done

if [[ -z "${TARGET}" ]]; then
  echo "usage: $0 user@host [--k3s|--k8s|--quick]" >&2
  exit 2
fi

ssh_host() { ssh "${SSH_OPTS[@]}" "$TARGET" "$@"; }
REMOTE_HOME="$(ssh_host 'printf %s "$HOME"')"
REMOTE_DIR="${REMOTE_HOME}/.deployments/netra"

log() { printf '[netra-deploy] %s\n' "$*"; }

if $VERIFY_ONLY; then
  ssh_host 'bash -s' <<'EOF'
set -euo pipefail
export KUBECONFIG="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"
kubectl -n netra-system get deploy,svc,pods
kubectl -n kube-system get deploy hubble-relay 2>/dev/null || true
curl -sf http://127.0.0.1:8080/healthz || kubectl -n netra-system port-forward svc/netra 8080:8080 >/tmp/netra-pf.log 2>&1 &
sleep 1
curl -sf http://127.0.0.1:8080/healthz
EOF
  exit 0
fi

log "sync → ${TARGET}:${REMOTE_DIR}"
if ! $DRY_RUN; then
  ssh_host "mkdir -p ${REMOTE_DIR}"
  rsync -az --delete \
    --exclude '.git' --exclude 'bin' --exclude 'web/node_modules' --exclude 'web/dist' \
    --exclude 'bpf/*.o' --exclude '.DS_Store' \
    "${ROOT}/" "${TARGET}:${REMOTE_DIR}/"
fi

remote_script=$(cat <<EOF
set -euo pipefail
cd ${REMOTE_DIR}
export PATH="/usr/local/bin:\$PATH"
PROFILE="${PROFILE}"

if [[ "\$PROFILE" == "k3s" ]]; then
  bash scripts/lib/ensure-cilium-k3s.sh
fi
bash scripts/lib/ensure-hubble-relay.sh

API_KEY="\${NETRA_API_KEY:-\$(openssl rand -hex 32)}"
AGENT_KEY="\${NETRA_AGENT_KEY:-\$(openssl rand -hex 32)}"

# Prefer pre-built images; otherwise build with docker/podman when available.
if command -v docker >/dev/null 2>&1; then
  docker build -t ghcr.io/zyvorai/netra:0.1.0 .
  if [[ "\${NETRA_AGENT_ENABLED:-false}" == "true" ]]; then
    docker build -f Dockerfile.agent -t ghcr.io/zyvorai/netra-agent:0.1.0 .
  fi
  if command -v k3s >/dev/null 2>&1; then
    docker save ghcr.io/zyvorai/netra:0.1.0 | k3s ctr images import -
  fi
fi

helm upgrade --install netra ./helm/netra \
  --namespace netra-system --create-namespace \
  --set auth.apiKey="\$API_KEY" \
  --set auth.agentKey="\$AGENT_KEY" \
  --set hubble.address=hubble-relay.kube-system.svc:80 \
  --wait --timeout 180s

kubectl -n netra-system rollout status deploy/netra --timeout=120s
echo "API_KEY=\$API_KEY"
echo "NETRA ready in netra-system (Hubble: hubble-relay.kube-system.svc:80)"
EOF
)

if $DRY_RUN; then
  log "dry-run remote script:"
  echo "$remote_script"
  exit 0
fi

ssh_host 'bash -s' <<<"$remote_script"
log "done. port-forward: kubectl -n netra-system port-forward svc/netra 8080:8080"
