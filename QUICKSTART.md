# Netra quick start

## Path A — Helm on an existing Cilium cluster

```bash
# Confirm Hubble Relay
kubectl -n kube-system get deploy hubble-relay

helm upgrade --install netra ./helm/netra \
  --namespace netra-system --create-namespace \
  --set auth.apiKey="$(openssl rand -hex 32)" \
  --set auth.agentKey="$(openssl rand -hex 32)"

kubectl -n netra-system port-forward svc/netra 30870:30870
curl -skf https://127.0.0.1:30870/livez
```

Open the UI at `https://127.0.0.1:30870` (self-signed TLS by default). Nav: **Overview**, **Pods**, **VMs**, **Policies**, **Live flows**, **eBPF**, **Audit**.

- **Pods / VMs** — pick a workload for scoped live flows, create/delete CNP rules, lock down / unlock.
- **Policies** — guided builder + JSON workbench with preflight receipts.
- **Live flows** — cluster-wide Hubble stream.

## Path B — Remote full stack (K3s + Cilium + Netra)

SSH host gets K3s (or uses existing), Cilium with Hubble Relay, then Netra via Helm. Image tag is reused (`0.7.0`); after deploy, restart the Deployment so the new layers are picked up:

```bash
NETRA_ALLOW_UNAUTHENTICATED=true ./scripts/deploy-remote.sh HOST USER --k8s
# if the pod did not pick up a same-tag image rebuild:
kubectl -n netra-system rollout restart deploy/netra
```

Or with the container helper:

```bash
./scripts/deploy-container.sh user@YOUR_HOST
```

## Path C — Local binaries

```bash
go run ./cmd/netrad
NETRA_URL=https://127.0.0.1:30870 go run ./cmd/netractl status
```

Requires reachable Kubernetes API + Hubble Relay (`NETRA_HUBBLE_ADDR`, default `hubble-relay.kube-system.svc:80`).

### Smoke APIs

```bash
curl -skf https://HOST:30870/api/v1/pods | head
curl -skf https://HOST:30870/api/v1/vms | head
curl -skf https://HOST:30870/api/v1/workloads/pod/default/PODNAME
```
