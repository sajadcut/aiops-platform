# Service Topology Knowledge Contract

Cognia is queried for service/deployment topology during Incident context construction even when the triggering source already contains useful metadata. This improves correlation and gives the reasoning layer an independent governed Knowledge view, while Live Evidence remains authoritative for current operational state.

## Why this exists

A sparse trigger can contain only a symptom and a public endpoint, for example:

```text
Problem: Download speed for "web.wepod.ir" has slowed down.
Host: wepod.ir
```

The Zabbix `Host` may be only the logical container that owns a Web Scenario. It is not automatically the runtime service. AIOps therefore searches Cognia for topology knowledge before using MCP sources to confirm the current runtime target.

## Recommended Cognia content

Topology knowledge should be stored in a compact line-oriented or JSON form so retrieval chunks preserve independently useful fields. Recommended line-oriented content:

```text
Service: web-api
URL: https://web.wepod.ir
Platform: Kubernetes
Cluster: prod-k8s
Namespace: wepod-prod
Workload Kind: Deployment
Workload: web-api
Repository: https://git.example/wepod/web-api.git
Jenkins Job: production/wepod/web-api
Owner: digital-platform
```

The deterministic parser recognizes only an allowlist of topology keys. It does not execute instructions or infer topology from arbitrary prose.

Supported canonical fields are:

- `fqdn` / `url` / `public_url` / `endpoint`
- `service` / `service_name` / `app`
- `platform`
- `cluster`
- `namespace`
- `workload_kind`
- `workload` / `deployment` / `statefulset` / `daemonset`
- `repository` / `repo` / `git_repository` / `scm`
- `jenkins_job` / `ci_job`
- `owner` / `team`

## Resolution policy

The runtime policy is deliberately asymmetric:

1. Cognia is queried for topology/discovery Knowledge even when the trigger or Live Evidence already looks sufficient.
2. A Cognia service mapping may be used to seed read-only Live Evidence lookup when the alert does not identify the service.
3. Live Zabbix/Elastic/Prometheus/Kubernetes/VM metadata wins when it conflicts with Cognia.
4. Placeholder live values such as `unknown`, `null` and `n/a` are treated as missing; they do not override a useful Cognia discovery hint.
5. Execution-sensitive identity fields are `service`, `platform`, `cluster`, `namespace`, `workload_kind` and `workload`. If any of those fields exists only in Cognia, it is marked `field_provenance=knowledge` and `requires_live_verification=true`.
6. Auxiliary fields such as `owner` may be enriched from Cognia without making an otherwise live-verified execution target unverified.
7. Live-vs-Knowledge and Knowledge-vs-Knowledge conflicts are preserved in `topology_context.conflicts`; they are never silently resolved in favor of Knowledge.
8. Knowledge-only topology may route read-only investigation, but it must not authorize restart/rollback/deploy/write operations. The Decision Engine rejects a mutating/approval-gated execution request while target identity remains unverified.
9. Repository and Jenkins Job values are deployment hints. Existence and current permission must be verified through the real Jenkins MCP before any Jenkins action is proposed or executed.

## Runtime context shape

Context construction exposes both the raw Live identity and the reconciled view:

```json
{
  "live_asset_context": {
    "hostname": "wepod.ir",
    "platform": "unknown"
  },
  "asset_context": {
    "hostname": "wepod.ir",
    "service": "web-api",
    "platform": "kubernetes",
    "namespace": "wepod-prod",
    "field_provenance": {
      "service": "knowledge",
      "platform": "knowledge",
      "namespace": "knowledge"
    },
    "knowledge_assisted": true,
    "requires_live_verification": true
  },
  "topology_context": {
    "knowledge_identity_fields": ["service", "platform", "cluster", "namespace", "workload_kind", "workload"],
    "deployment_hints": {
      "fqdn": "web.wepod.ir",
      "repository": "https://git.example/wepod/web-api.git",
      "jenkins_job": "production/wepod/web-api"
    },
    "execution_policy": "knowledge_identity_topology_must_be_live_verified_before_write"
  }
}
```

Once MCP evidence confirms the same platform/namespace/workload, those fields are live-provenanced and no longer count as unverified Knowledge identity. If the live system reports a different namespace or workload, the live value is retained and the Cognia mismatch becomes an explicit topology conflict that must be investigated and should normally lead to updating the governed Knowledge record.
