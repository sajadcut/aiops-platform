from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import httpx

from domain.contracts.config import settings


class KubernetesEvidenceClient:
    """Strictly read-only Kubernetes API evidence client.

    Only HTTP GET requests are implemented. The service account used by this
    connector should have GET/LIST-only RBAC for pods/events and pod logs.
    """

    def __init__(
        self,
        api_url: Optional[str] = None,
        token: Optional[str] = None,
        namespace: Optional[str] = None,
    ):
        self.api_url = (api_url if api_url is not None else settings.KUBERNETES_API_URL) or ""
        self.namespace = namespace or settings.KUBERNETES_NAMESPACE
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

    def _verify(self):
        return settings.KUBERNETES_CA_CERT_PATH or True

    async def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        if not self.enabled:
            raise RuntimeError("kubernetes_evidence_connector_disabled")
        async with httpx.AsyncClient(
            timeout=settings.KUBERNETES_TIMEOUT_SECONDS,
            verify=self._verify(),
            headers=self._headers(),
        ) as client:
            response = await client.get(self.api_url.rstrip("/") + path, params=params)
            response.raise_for_status()
            content_type = response.headers.get("content-type", "")
            return response.json() if "json" in content_type else response.text

    async def list_pods(self, service: str) -> List[Dict[str, Any]]:
        data = await self._get(
            f"/api/v1/namespaces/{quote(self.namespace, safe='')}/pods",
            params={"labelSelector": f"app={service}"},
        )
        return list(data.get("items", [])) if isinstance(data, dict) else []

    async def list_events(self, service: str) -> List[Dict[str, Any]]:
        data = await self._get(
            f"/api/v1/namespaces/{quote(self.namespace, safe='')}/events",
            params={"fieldSelector": f"involvedObject.namespace={self.namespace}"},
        )
        events = list(data.get("items", [])) if isinstance(data, dict) else []
        filtered = []
        for event in events:
            involved = event.get("involvedObject") or {}
            name = str(involved.get("name") or "")
            labels = (event.get("metadata") or {}).get("labels") or {}
            if service in name or labels.get("app") == service:
                filtered.append(event)
        return filtered

    async def pod_logs(self, pod_name: str) -> str:
        data = await self._get(
            f"/api/v1/namespaces/{quote(self.namespace, safe='')}/pods/{quote(pod_name, safe='')}/log",
            params={"tailLines": settings.KUBERNETES_LOG_TAIL_LINES, "timestamps": "true"},
        )
        return str(data)

    async def collect_evidence(self, service: str) -> List[Dict[str, Any]]:
        pods = await self.list_pods(service)
        events = await self.list_events(service)
        evidence: List[Dict[str, Any]] = []

        for pod in pods:
            metadata = pod.get("metadata") or {}
            status = pod.get("status") or {}
            name = str(metadata.get("name") or "")
            evidence.append({
                "type": "kubernetes_pod",
                "source": "kubernetes_api",
                "reference": f"k8s:pod:{self.namespace}:{name}",
                "timestamp": status.get("startTime") or metadata.get("creationTimestamp"),
                "raw_data": {
                    "metadata": {"name": name, "namespace": self.namespace, "labels": metadata.get("labels", {})},
                    "status": status,
                    "spec": {"nodeName": (pod.get("spec") or {}).get("nodeName")},
                },
            })
            if name:
                try:
                    logs = await self.pod_logs(name)
                except httpx.HTTPError:
                    logs = ""
                if logs:
                    evidence.append({
                        "type": "log",
                        "source": "kubernetes_api",
                        "reference": f"k8s:log:{self.namespace}:{name}",
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
