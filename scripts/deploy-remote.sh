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
# UI/API default NodePort/host access: :30870
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PROFILE="k3s"
DRY_RUN=false
VERIFY_ONLY=false
TARGET=""
TARGET_USER=""
POSITIONAL=()
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
      POSITIONAL+=("$1")
      shift
      ;;
  esac
done

if [[ ${#POSITIONAL[@]} -eq 1 ]]; then
  TARGET="${POSITIONAL[0]}"
elif [[ ${#POSITIONAL[@]} -eq 2 ]]; then
  # ./scripts/deploy-remote.sh HOST USER
  if [[ "${POSITIONAL[0]}" == *@* ]]; then
    TARGET="${POSITIONAL[0]}"
  elif [[ "${POSITIONAL[1]}" == *@* ]]; then
    TARGET="${POSITIONAL[1]}"
  else
    TARGET="${POSITIONAL[1]}@${POSITIONAL[0]}"
  fi
elif [[ ${#POSITIONAL[@]} -gt 2 ]]; then
  echo "usage: $0 user@host [--k8s]   or   $0 HOST USER [--k8s]" >&2
  exit 2
fi

if [[ -z "${TARGET}" ]]; then
  echo "usage: $0 user@host [--k3s|--k8s|--quick]" >&2
  echo "   or: $0 HOST USER [--k8s]" >&2
  exit 2
fi

ALLOW_UNAUTH_LOCAL="${NETRA_ALLOW_UNAUTHENTICATED:-false}"

ssh_host() { ssh "${SSH_OPTS[@]}" "$TARGET" "$@"; }
REMOTE_HOME="$(ssh_host 'printf %s "$HOME"')"
REMOTE_DIR="${REMOTE_HOME}/.deployments/netra"

log() { printf '[netra-deploy] %s\n' "$*"; }

if $VERIFY_ONLY; then
  ssh_host 'bash -s' <<'EOF'
set -euo pipefail
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/netra-k3s.yaml}"
if [[ ! -r "${KUBECONFIG}" ]]; then
  mkdir -p "$HOME/.kube"
  sudo cat /etc/rancher/k3s/k3s.yaml | sed "s/127.0.0.1/$(hostname -I | awk '{print $1}')/" > "$HOME/.kube/netra-k3s.yaml"
  chmod 600 "$HOME/.kube/netra-k3s.yaml"
  export KUBECONFIG="$HOME/.kube/netra-k3s.yaml"
fi
kubectl -n netra-system get deploy,svc,pods
kubectl -n kube-system get deploy hubble-relay 2>/dev/null || true
curl -skf https://127.0.0.1:30870/healthz
EOF
  exit 0
fi

log "sync → ${TARGET}:${REMOTE_DIR}"
if ! $DRY_RUN; then
  ssh_host "mkdir -p ${REMOTE_DIR}"
  rsync -az --delete \
    --exclude '.git' --exclude 'bin' --exclude 'web/node_modules' --exclude 'web/dist' \
    --exclude 'bpf/*.o' --exclude '.DS_Store' --exclude '.cursor' \
    "${ROOT}/" "${TARGET}:${REMOTE_DIR}/"
fi

remote_script=$(cat <<EOF
set -euo pipefail
cd ${REMOTE_DIR}
export PATH="/usr/local/bin:\$HOME/go/bin:/usr/bin:\$PATH"
PROFILE="${PROFILE}"

mkdir -p "\$HOME/.kube"
if [[ ! -r "\$HOME/.kube/netra-k3s.yaml" ]] || [[ /etc/rancher/k3s/k3s.yaml -nt "\$HOME/.kube/netra-k3s.yaml" ]]; then
  sudo cat /etc/rancher/k3s/k3s.yaml > "\$HOME/.kube/netra-k3s.yaml"
  chmod 600 "\$HOME/.kube/netra-k3s.yaml"
fi
export KUBECONFIG="\$HOME/.kube/netra-k3s.yaml"

if [[ "\$PROFILE" == "k3s" ]]; then
  bash scripts/lib/ensure-cilium-k3s.sh
fi
bash scripts/lib/ensure-hubble-relay.sh

ALLOW_UNAUTH="${ALLOW_UNAUTH_LOCAL}"
API_KEY="\${NETRA_API_KEY:-\$(openssl rand -hex 32)}"
AGENT_KEY="\${NETRA_AGENT_KEY:-\$(openssl rand -hex 32)}"
mkdir -p "\$HOME/.netra"
printf '%s\n' "\$API_KEY" > "\$HOME/.netra/api-key"
printf '%s\n' "\$AGENT_KEY" > "\$HOME/.netra/agent-key"
chmod 600 "\$HOME/.netra/"* || true

export GOTOOLCHAIN=auto
export PATH="/usr/local/go/bin:\$PATH"

build_image() {
  # Prefer host Go + npm then a thin runtime image.
  local runtime=""
  if command -v podman >/dev/null 2>&1; then
    runtime=podman
  elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    runtime=docker
  fi
  if command -v go >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
    echo "Building Netra on host with \$(go version) (GOTOOLCHAIN=\$GOTOOLCHAIN)..."
    npm --prefix web install
    npm --prefix web run build
    mkdir -p bin
    CGO_ENABLED=0 go build -o bin/netrad ./cmd/netrad
    CGO_ENABLED=0 go build -o bin/netractl ./cmd/netractl
    if [[ -z "\$runtime" ]]; then
      echo "podman or working docker required to build controller image" >&2
      exit 1
    fi
    \$runtime build -f Dockerfile.runtime -t ghcr.io/zyvorai/netra:0.19.0 .
    return 0
  fi
  if [[ -z "\$runtime" ]]; then
    echo "podman or working docker required to build controller image" >&2
    exit 1
  fi
  \$runtime build -t ghcr.io/zyvorai/netra:0.19.0 .
}

import_image() {
  if command -v podman >/dev/null 2>&1; then
    podman save ghcr.io/zyvorai/netra:0.19.0 | sudo k3s ctr images import -
  else
    docker save ghcr.io/zyvorai/netra:0.19.0 | sudo k3s ctr images import -
  fi
}

if [[ "\$PROFILE" != "quick" ]]; then
  build_image
  import_image
fi

HELM_AUTH=(--set "auth.apiKey=\$API_KEY" --set "auth.agentKey=\$AGENT_KEY")
if [[ "\$ALLOW_UNAUTH" == "true" ]]; then
  HELM_AUTH=(--set auth.allowUnauthenticated=true --set auth.apiKey="" --set auth.agentKey="")
fi

helm upgrade --install netra ./helm/netra \
  --namespace netra-system --create-namespace \
  "\${HELM_AUTH[@]}" \
  --set image.repository=ghcr.io/zyvorai/netra \
  --set image.tag=0.19.0 \
  --set image.pullPolicy=IfNotPresent \
  --set hubble.address=hubble-relay.kube-system.svc:80 \
  --set service.type=NodePort \
  --set service.port=30870 \
  --set service.nodePort=30870 \
  --set cilium.enabled=true \
  --set hubble.enabled=true \
  --wait --timeout 300s

kubectl -n netra-system rollout status deploy/netra --timeout=180s
echo "API_KEY=\$API_KEY"
echo "NETRA_URL=https://\$(hostname -I | awk '{print \$1}'):30870"
echo "NETRA ready (Hubble Relay + Cilium, HTTPS)"
curl -skf "https://127.0.0.1:30870/healthz" || curl -skf "https://\$(hostname -I | awk '{print \$1}'):30870/healthz"
EOF
)

if $DRY_RUN; then
  log "dry-run remote script:"
  echo "$remote_script"
  exit 0
fi

ssh_host 'bash -s' <<<"$remote_script"
log "done — open https://<host>:30870"
