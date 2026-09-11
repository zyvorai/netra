# Plain Kubernetes install

The plain manifests are secure by default. Create the authentication Secret before applying the controller:

```bash
kubectl create namespace netra-system --dry-run=client -o yaml | kubectl apply -f -
kubectl -n netra-system create secret generic netra-auth \
  --from-literal=api-key="$(openssl rand -hex 32)" \
  --from-literal=agent-key="$(openssl rand -hex 32)"
kubectl apply -k deploy/
```

`deploy/kustomization.yaml` intentionally does not include `agent.yaml`. Enable the privileged node agent only after validating Linux/TCX support and the target interface, then apply `deploy/agent.yaml` separately.

For a local-only unauthenticated development deployment, set `NETRA_ALLOW_UNAUTHENTICATED=true` explicitly and provide empty key values yourself. Do not use that mode on a shared cluster.

Policy apply is guarded by server-issued preflight receipts by default (`NETRA_REQUIRE_PREFLIGHT=true`). Keep this enabled in shared/production clusters; the Helm equivalent is `policy.requirePreflight=true`.

Workload inventory (Pods / KubeVirt VMs) and lockdown need the ClusterRole verbs in `deploy/rbac.yaml` / Helm `templates/rbac.yaml` (`pods`, `apps/*` get/list, optional `kubevirt.io`). After applying RBAC changes, restart the controller Deployment.

The plain kustomization includes `pvc.yaml` and configures `NETRA_STATE_FILE=/var/lib/netra/state.json`. A default StorageClass (or an edited PVC) is therefore required. The plain manifest remains a simple **single-controller** installation. For v0.6 active/passive HA, use the Helm chart so Lease election, leader-only readiness, PodDisruptionBudget, anti-affinity and RWX validation are rendered together. HA requires a shared ReadWriteMany volume with reliable POSIX advisory locking.
