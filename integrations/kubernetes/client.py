from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx
from integrations.http_transport import insecure_async_client

from domain.contracts.config import settings


class KubernetesEvidenceClient:
    """Strictly read-only Kubernetes API evidence client.

    Only HTTP GET requests are implemented. The service account used by this
    connector should have GET/LIST-only RBAC for pods, deployments, events,
    metrics and pod logs. The Control Plane never imports this client directly;
    it is composed only inside the Kubernetes MCP server boundary.
    """

    _OPERATIONS = {
        "list_pods",
        "pod_status",
        "deployment_status",
        "events",
        "resource_usage",
        "rollout_state",
        "service_evidence",
    }

    def __init__(
        self,
        api_url: Optional[str] = None,
        token: Optional[str] = None,
        namespace: Optional[str] = None,
    ):
        self.api_url = (api_url if api_url is not None else settings.KUBERNETES_API_URL) or ""
        self.namespace = str(namespace or settings.KUBERNETES_NAMESPACE or "default").strip()
        self.token = token if token is not None else settings.KUBERNETES_TOKEN
        if not self.token and settings.KUBERNETES_TOKEN_FILE:
            path = Path(settings.KUBERNETES_TOKEN_FILE)
            if path.exists():
                self.token = path.read_text(encoding="utf-8").strip()

    @property
    def enabled(self) -> bool:
        return bool(self.api_url)

    def _headers(self) -> Dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    @staticmethod
    def _namespace(value: Optional[str], fallback: str) -> str:
        namespace = str(value or fallback or "").strip()
        if not namespace:
            raise ValueError("namespace_required")
        return namespace

    async def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        if not self.enabled:
            raise RuntimeError("kubernetes_evidence_connector_disabled")
        async with insecure_async_client(
            timeout=settings.KUBERNETES_TIMEOUT_SECONDS,
            headers=self._headers(),
        ) as client:
            response = await client.get(self.api_url.rstrip("/") + path, params=params)
            response.raise_for_status()
            content_type = response.headers.get("content-type", "")
            return response.json() if "json" in content_type else response.text

    async def list_pods(self, service: Optional[str] = None, namespace: Optional[str] = None) -> List[Dict[str, Any]]:
        ns = self._namespace(namespace, self.namespace)
        params: Dict[str, Any] = {}
        service_name = str(service or "").strip()
        if service_name:
            params["labelSelector"] = f"app={service_name}"
        data = await self._get(
            f"/api/v1/namespaces/{quote(ns, safe='')}/pods",
            params=params or None,
        )
        return list(data.get("items", [])) if isinstance(data, dict) else []

    async def get_pod(self, pod_name: str, namespace: Optional[str] = None) -> Dict[str, Any]:
        ns = self._namespace(namespace, self.namespace)
        name = str(pod_name or "").strip()
        if not name:
            raise ValueError("pod_name_required")
        data = await self._get(
            f"/api/v1/namespaces/{quote(ns, safe='')}/pods/{quote(name, safe='')}"
        )
        return dict(data) if isinstance(data, dict) else {"raw": data}

    async def list_events(self, service: Optional[str] = None, namespace: Optional[str] = None) -> List[Dict[str, Any]]:
        ns = self._namespace(namespace, self.namespace)
        data = await self._get(
            f"/api/v1/namespaces/{quote(ns, safe='')}/events",
            params={"fieldSelector": f"involvedObject.namespace={ns}"},
        )
        events = list(data.get("items", [])) if isinstance(data, dict) else []
        service_name = str(service or "").strip()
        if not service_name:
            return events
        filtered = []
        for event in events:
            involved = event.get("involvedObject") or {}
            name = str(involved.get("name") or "")
            labels = (event.get("metadata") or {}).get("labels") or {}
            if service_name in name or labels.get("app") == service_name:
                filtered.append(event)
        return filtered

    async def pod_logs(self, pod_name: str, namespace: Optional[str] = None) -> str:
        ns = self._namespace(namespace, self.namespace)
        data = await self._get(
            f"/api/v1/namespaces/{quote(ns, safe='')}/pods/{quote(pod_name, safe='')}/log",
            params={"tailLines": settings.KUBERNETES_LOG_TAIL_LINES, "timestamps": "true"},
        )
        return str(data)

    async def get_deployment(self, name: str, namespace: Optional[str] = None) -> Dict[str, Any]:
        ns = self._namespace(namespace, self.namespace)
        deployment = str(name or "").strip()
        if not deployment:
            raise ValueError("deployment_name_required")
        data = await self._get(
            f"/apis/apps/v1/namespaces/{quote(ns, safe='')}/deployments/{quote(deployment, safe='')}"
        )
        return dict(data) if isinstance(data, dict) else {"raw": data}

    async def resource_usage(self, namespace: Optional[str] = None) -> List[Dict[str, Any]]:
        ns = self._namespace(namespace, self.namespace)
        data = await self._get(
            f"/apis/metrics.k8s.io/v1beta1/namespaces/{quote(ns, safe='')}/pods"
        )
        return list(data.get("items", [])) if isinstance(data, dict) else []

    @staticmethod
    def _pod_summary(pod: Dict[str, Any]) -> Dict[str, Any]:
        metadata = pod.get("metadata") or {}
        status = pod.get("status") or {}
        spec = pod.get("spec") or {}
        container_statuses = status.get("containerStatuses") or []
        return {
            "name": metadata.get("name"),
            "namespace": metadata.get("namespace"),
            "labels": metadata.get("labels") or {},
            "phase": status.get("phase"),
            "pod_ip": status.get("podIP"),
            "host_ip": status.get("hostIP"),
            "node": spec.get("nodeName"),
            "start_time": status.get("startTime"),
            "containers": [
                {
                    "name": item.get("name"),
                    "ready": item.get("ready"),
                    "restart_count": item.get("restartCount"),
                    "state": item.get("state"),
                }
                for item in container_statuses
                if isinstance(item, dict)
            ],
        }

    @staticmethod
    def _deployment_summary(deployment: Dict[str, Any]) -> Dict[str, Any]:
        metadata = deployment.get("metadata") or {}
        spec = deployment.get("spec") or {}
        status = deployment.get("status") or {}
        return {
            "name": metadata.get("name"),
            "namespace": metadata.get("namespace"),
            "generation": metadata.get("generation"),
            "observed_generation": status.get("observedGeneration"),
            "desired_replicas": spec.get("replicas"),
            "replicas": status.get("replicas"),
            "updated_replicas": status.get("updatedReplicas"),
            "ready_replicas": status.get("readyReplicas"),
            "available_replicas": status.get("availableReplicas"),
            "unavailable_replicas": status.get("unavailableReplicas"),
            "conditions": status.get("conditions") or [],
        }

    async def collect_query(
        self,
        *,
        operation: str,
        namespace: Optional[str] = None,
        service: Optional[str] = None,
        resource: Optional[str] = None,
    ) -> Any:
        op = str(operation or "service_evidence").strip()
        if op not in self._OPERATIONS:
            raise ValueError("unsupported_kubernetes_read_operation")
        ns = self._namespace(namespace, self.namespace)
        if op == "list_pods":
            return [self._pod_summary(item) for item in await self.list_pods(service=service, namespace=ns)]
        if op == "pod_status":
            return self._pod_summary(await self.get_pod(str(resource or ""), namespace=ns))
        if op == "deployment_status":
            return self._deployment_summary(await self.get_deployment(str(resource or ""), namespace=ns))
        if op == "events":
            return await self.list_events(service=service, namespace=ns)
        if op == "resource_usage":
            return await self.resource_usage(namespace=ns)
        if op == "rollout_state":
            summary = self._deployment_summary(await self.get_deployment(str(resource or ""), namespace=ns))
            desired = int(summary.get("desired_replicas") or 0)
            ready = int(summary.get("ready_replicas") or 0)
            updated = int(summary.get("updated_replicas") or 0)
            observed = summary.get("observed_generation")
            generation = summary.get("generation")
            summary["rollout_complete"] = bool(desired == ready == updated and observed == generation)
            return summary
        service_name = str(service or "").strip()
        if not service_name:
            raise ValueError("service_required")
        return await self.collect_evidence(service_name, namespace=ns)

    async def collect_evidence(self, service: str, namespace: Optional[str] = None) -> List[Dict[str, Any]]:
        ns = self._namespace(namespace, self.namespace)
        pods = await self.list_pods(service, namespace=ns)
        events = await self.list_events(service, namespace=ns)
        evidence: List[Dict[str, Any]] = []

        for pod in pods:
            metadata = pod.get("metadata") or {}
            status = pod.get("status") or {}
            name = str(metadata.get("name") or "")
            evidence.append({
                "type": "kubernetes_pod",
                "source": "kubernetes_api",
                "reference": f"k8s:pod:{ns}:{name}",
                "timestamp": status.get("startTime") or metadata.get("creationTimestamp"),
                "raw_data": {
                    "metadata": {"name": name, "namespace": ns, "labels": metadata.get("labels", {})},
                    "status": status,
                    "spec": {"nodeName": (pod.get("spec") or {}).get("nodeName")},
                },
            })
            if name:
                try:
                    logs = await self.pod_logs(name, namespace=ns)
                except httpx.HTTPError:
                    logs = ""
                if logs:
                    evidence.append({
                        "type": "log",
                        "source": "kubernetes_api",
                        "reference": f"k8s:log:{ns}:{name}",
                        "raw_data": {"pod": name, "log": logs},
                    })

        for event in events:
            metadata = event.get("metadata") or {}
            evidence.append({
                "type": "event",
                "source": "kubernetes_api",
                "reference": f"k8s:event:{metadata.get('uid') or metadata.get('name')}",
                "timestamp": event.get("eventTime") or event.get("lastTimestamp") or metadata.get("creationTimestamp"),
                "raw_data": event,
            })
        return evidence
