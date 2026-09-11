# Plain Kubernetes install

The base plain manifests are standalone and do **not** grant Cilium permissions. The controller receives read-only `get/list pods` access for workload attribution; the privileged agent remains tokenless.

Create controller/agent credentials first:

```bash
kubectl create namespace netra-system --dry-run=client -o yaml | kubectl apply -f -
kubectl -n netra-system create secret generic netra-auth \
  --from-literal=api-key="$(openssl rand -hex 32)" \
  --from-literal=agent-key="$(openssl rand -hex 32)"
kubectl apply -k deploy/
```

`deploy/kustomization.yaml` intentionally leaves the privileged `agent.yaml` disabled. Validate cgroup v2, bpffs and kernel BPF support, then enable standalone eBPF coverage:

```bash
kubectl apply -f deploy/agent.yaml
```

The default agent uses root-cgroup hooks and requires no CNI-specific interface. It rescans cgroup-v2 metadata every `NETRA_CGROUP_SCAN_INTERVAL` (default `10s`) so pod/container churn can be attributed without restarting the DaemonSet. TCX/XDP can be enabled by editing `NETRA_INTERFACES` / `NETRA_XDP_INTERFACES` in `agent.yaml`.

Cilium policy integration is optional. When needed, grant its RBAC separately:

```bash
kubectl apply -f deploy/rbac-cilium.yaml
kubectl -n netra-system set env deployment/netra NETRA_CILIUM_ENABLED=true
```

Hubble is disabled in the base controller manifest. Set `NETRA_HUBBLE_ENABLED=true` and configure `NETRA_HUBBLE_ADDR` only when Hubble Relay is available.

The plain deployment includes a PVC and remains a simple single-controller install. Use the Helm chart for the active/passive HA topology, which validates the shared RWX state assumptions and renders Lease election, anti-affinity and the PDB together.
