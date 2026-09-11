# Netra quick start

## Path A — Helm on an existing Cilium cluster

```bash
# Confirm Hubble Relay
kubectl -n kube-system get deploy hubble-relay

helm upgrade --install netra ./helm/netra \
  --namespace netra-system --create-namespace \
  --set auth.apiKey="$(openssl rand -hex 32)" \
  --set auth.agentKey="$(openssl rand -hex 32)"

kubectl -n netra-system port-forward svc/netra 8080:8080
curl -sf http://127.0.0.1:8080/healthz
```

## Path B — Remote full stack (K3s + Cilium + Netra)

Same pattern as PacketWolf’s container deploy: SSH host gets K3s without flannel, Cilium 1.20 with Hubble Relay, then Netra via Helm.

```bash
./scripts/deploy-container.sh user@YOUR_HOST
```

## Path C — Local binaries

```bash
go run ./cmd/netrad
NETRA_URL=http://127.0.0.1:8080 go run ./cmd/netractl status
```

Requires reachable Kubernetes API + Hubble Relay (`NETRA_HUBBLE_ADDR`, default `hubble-relay.kube-system.svc:80`).
