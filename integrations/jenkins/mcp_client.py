from __future__ import annotations

from typing import Any, Dict, Mapping, Optional

from domain.contracts.config import settings
from domain.contracts.logging import logger
from integrations.mcp_client import MCPClient


class JenkinsMCPClient(MCPClient):
    """Governed client for the official Jenkins ``mcp-server`` plugin.

    The upstream plugin exposes Jenkins over MCP Streamable HTTP at
    ``/mcp-server/mcp`` and authenticates with the Jenkins user's API token via
    a complete HTTP Basic ``Authorization`` header.

    Read tools are available through the normal MCP identity. Mutating Jenkins
    tools are disabled by default and, when explicitly enabled, require a
    separate write identity plus local Approval/incident/execution-capability
    context. Those governance values are deliberately not forwarded to Jenkins
    because they are AIOps Control-Plane evidence, not parameters in the
    upstream Jenkins MCP tool schema.
    """

    READ_TOOLS = frozenset(
        {
            "getJob",
            "getJobs",
            "getQueueItem",
            "getBuild",
            "getBuildLog",
            "searchBuildLog",
            "getReplayScripts",
            "getTestResults",
            "getJobScm",
            "getBuildScm",
            "getBuildChangeSets",
            "findJobsWithScmUrl",
            "whoAmI",
            "getStatus",
        }
    )
    WRITE_TOOLS = frozenset({"triggerBuild", "updateBuild", "rebuildBuild", "replayBuild"})

    def __init__(
        self,
        server_url: Optional[str] = None,
        *,
        authorization_header: Optional[str] = None,
        write_authorization_header: Optional[str] = None,
        expected_identity: Optional[str] = None,
        origin: Optional[str] = None,
        enable_writes: Optional[bool] = None,
    ):
        url = str(server_url or settings.JENKINS_MCP_URL or "").strip()
        if not url:
            raise ValueError("jenkins_mcp_url_not_configured")

        self.expected_identity = str(
            expected_identity if expected_identity is not None else settings.JENKINS_MCP_EXPECTED_IDENTITY or ""
        ).strip() or None
        self.origin = str(origin if origin is not None else settings.JENKINS_MCP_ORIGIN or "").strip() or None
        self.enable_writes = bool(settings.JENKINS_MCP_ENABLE_WRITES if enable_writes is None else enable_writes)

        read_auth = str(
            authorization_header if authorization_header is not None else settings.JENKINS_MCP_AUTH_HEADER or ""
        ).strip() or None
        write_auth = str(
            write_authorization_header
            if write_authorization_header is not None
            else settings.JENKINS_MCP_WRITE_AUTH_HEADER or ""
        ).strip() or None
        if self.enable_writes and not write_auth:
            raise ValueError("jenkins_mcp_write_auth_header_required")

        allowed_tools = set(self.READ_TOOLS)
        write_tools: set[str] = set()
        if self.enable_writes:
            allowed_tools.update(self.WRITE_TOOLS)
            write_tools.update(self.WRITE_TOOLS)

        super().__init__(
            url,
            "jenkins",
            allowed_tools=allowed_tools,
            write_tools=write_tools,
            protocol_version=settings.JENKINS_MCP_PROTOCOL_VERSION,
            timeout=settings.MCP_TIMEOUT_SECONDS,
            authorization_header=read_auth,
            write_authorization_header=write_auth,
            client_cert_path=settings.MCP_CLIENT_CERT_PATH,
            client_key_path=settings.MCP_CLIENT_KEY_PATH,
        )

    def _headers(self, *, tool_name: Optional[str] = None, include_protocol: bool = True) -> Dict[str, str]:
        headers = super()._headers(tool_name=tool_name, include_protocol=include_protocol)
        if self.origin:
            headers["Origin"] = self.origin
        return headers

    @property
    def health_url(self) -> str:
        for suffix in ("/mcp-server/mcp", "/mcp-server/stateless", "/mcp-server/sse"):
            if self.server_url.rstrip("/").endswith(suffix):
                base = self.server_url.rstrip("/")[: -len(suffix)]
                return f"{base}/mcp-health"
        raise ValueError("jenkins_mcp_endpoint_path_invalid")

    @staticmethod
    def _decoded(result: Dict[str, Any]) -> Any:
        values = MCPClient.json_content(result)
        if not values:
            return {}
        if len(values) == 1:
            return values[0]
        return values

    @staticmethod
    def _with_optional(arguments: Dict[str, Any], **values: Any) -> Dict[str, Any]:
        for key, value in values.items():
            if value is not None:
                arguments[key] = value
        return arguments

    @staticmethod
    def _require_write_context(approval_id: str, incident_id: str, execution_capability: str) -> None:
        if not str(approval_id or "").strip():
            raise PermissionError("jenkins_write_approval_id_required")
        if not str(incident_id or "").strip():
            raise PermissionError("jenkins_write_incident_id_required")
        if not str(execution_capability or "").strip():
            raise PermissionError("jenkins_write_execution_capability_required")

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        if tool_name in self.WRITE_TOOLS:
            raise PermissionError(f"jenkins_write_requires_governed_method:{tool_name}")
        return await super().call_tool(tool_name, arguments)

    async def _read_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        return self._decoded(await self.call_tool(name, arguments))

    async def _write_tool(
        self,
        name: str,
        arguments: Dict[str, Any],
        *,
        approval_id: str,
        incident_id: str,
        execution_capability: str,
    ) -> Any:
        if not self.enable_writes:
            raise PermissionError("jenkins_mcp_writes_disabled")
        self._require_write_context(approval_id, incident_id, execution_capability)
        return self._decoded(await super().call_tool(name, arguments))

    async def mcp_health(self) -> Dict[str, Any]:
        headers = {"Accept": "application/json"}
        if self.origin:
            headers["Origin"] = self.origin
        response = await self._client.get(self.health_url, headers=headers)
        if response.status_code not in {200, 503}:
            response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict):
            return {"mcpServerStatus": "invalid_response", "shuttingDown": True}
        payload["httpStatus"] = response.status_code
        retry_after = response.headers.get("Retry-After")
        if retry_after:
            payload["retryAfter"] = retry_after
        return payload

    async def who_am_i(self) -> Dict[str, Any]:
        payload = await self._read_tool("whoAmI", {})
        return payload if isinstance(payload, dict) else {"fullName": str(payload)}

    async def get_status(self) -> Dict[str, Any]:
        payload = await self._read_tool("getStatus", {})
        return payload if isinstance(payload, dict) else {"value": payload}

    async def health_check(self) -> bool:
        try:
            status = await self.mcp_health()
            if status.get("httpStatus") != 200:
                return False
            if str(status.get("mcpServerStatus") or "").lower() != "ok":
                return False
            if bool(status.get("shuttingDown")):
                return False

            identity = await self.who_am_i()
            actual = str(identity.get("fullName") or "").strip()
            if not actual or actual.lower() == "anonymous":
                return False
            if self.expected_identity and actual != self.expected_identity:
                logger.warning(
                    "jenkins_mcp_identity_mismatch",
                    expected=self.expected_identity,
                    actual=actual,
                )
                return False
            return True
        except Exception as exc:
            logger.warning("jenkins_mcp_health_failed", error_type=type(exc).__name__)
            return False

    async def get_job(self, job_full_name: str) -> Any:
        return await self._read_tool("getJob", {"jobFullName": job_full_name})

    async def get_jobs(self, parent_full_name: Optional[str] = None, *, skip: int = 0, limit: int = 10) -> Any:
        arguments: Dict[str, Any] = {
            "skip": max(0, int(skip)),
            "limit": min(max(int(limit), 1), 10),
        }
        if parent_full_name:
            arguments["parentFullName"] = parent_full_name
        return await self._read_tool("getJobs", arguments)

    async def get_queue_item(self, queue_item_id: int) -> Any:
        return await self._read_tool("getQueueItem", {"id": int(queue_item_id)})

    async def get_build(self, job_full_name: str, build_number: Optional[int] = None) -> Any:
        return await self._read_tool(
            "getBuild",
            self._with_optional({"jobFullName": job_full_name}, buildNumber=build_number),
        )

    async def get_build_log(
        self,
        job_full_name: str,
        build_number: Optional[int] = None,
        *,
        skip: Optional[int] = None,
        limit: int = 100,
        cursor: Optional[str] = None,
    ) -> Any:
        bounded_limit = max(-1000, min(int(limit), 1000))
        if bounded_limit == 0:
            bounded_limit = 100
        arguments = self._with_optional(
            {"jobFullName": job_full_name, "limit": bounded_limit},
            buildNumber=build_number,
            skip=skip,
            cursor=cursor,
        )
        return await self._read_tool("getBuildLog", arguments)

    async def search_build_log(
        self,
        job_full_name: str,
        pattern: str,
        build_number: Optional[int] = None,
        *,
        use_regex: bool = False,
        ignore_case: bool = False,
        max_matches: int = 100,
        context_lines: int = 0,
    ) -> Any:
        if not str(pattern or ""):
            raise ValueError("jenkins_build_log_pattern_required")
        arguments = self._with_optional(
            {
                "jobFullName": job_full_name,
                "pattern": pattern,
                "useRegex": bool(use_regex),
                "ignoreCase": bool(ignore_case),
                "maxMatches": min(max(int(max_matches), 1), 200),
                "contextLines": min(max(int(context_lines), 0), 5),
            },
            buildNumber=build_number,
        )
        return await self._read_tool("searchBuildLog", arguments)

    async def get_replay_scripts(self, job_full_name: str, build_number: Optional[int] = None) -> Any:
        return await self._read_tool(
            "getReplayScripts",
            self._with_optional({"jobFullName": job_full_name}, buildNumber=build_number),
        )

    async def get_test_results(self, job_full_name: str, build_number: Optional[int] = None) -> Any:
        return await self._read_tool(
            "getTestResults",
            self._with_optional({"jobFullName": job_full_name}, buildNumber=build_number),
        )

    async def get_job_scm(self, job_full_name: str) -> Any:
        return await self._read_tool("getJobScm", {"jobFullName": job_full_name})

    async def get_build_scm(self, job_full_name: str, build_number: Optional[int] = None) -> Any:
        return await self._read_tool(
            "getBuildScm",
            self._with_optional({"jobFullName": job_full_name}, buildNumber=build_number),
        )

    async def get_build_change_sets(self, job_full_name: str, build_number: Optional[int] = None) -> Any:
        return await self._read_tool(
            "getBuildChangeSets",
            self._with_optional({"jobFullName": job_full_name}, buildNumber=build_number),
        )

    async def find_jobs_with_scm_url(
        self,
        scm_url: str,
        *,
        branch: Optional[str] = None,
        skip: int = 0,
        limit: int = 10,
    ) -> Any:
        arguments = self._with_optional(
            {
                "scmUrl": scm_url,
                "skip": max(0, int(skip)),
                "limit": min(max(int(limit), 1), 10),
            },
            branch=branch,
        )
        return await self._read_tool("findJobsWithScmUrl", arguments)

    async def trigger_build(
        self,
        job_full_name: str,
        *,
        parameters: Optional[Mapping[str, Any]] = None,
        approval_id: str,
        incident_id: str,
        execution_capability: str,
    ) -> Any:
        return await self._write_tool(
            "triggerBuild",
            {"jobFullName": job_full_name, "parameters": dict(parameters or {})},
            approval_id=approval_id,
            incident_id=incident_id,
            execution_capability=execution_capability,
        )

    async def update_build(
        self,
        job_full_name: str,
        *,
        build_number: Optional[int] = None,
        display_name: Optional[str] = None,
        description: Optional[str] = None,
        approval_id: str,
        incident_id: str,
        execution_capability: str,
    ) -> Any:
        if not display_name and not description:
            raise ValueError("jenkins_update_build_change_required")
        arguments = self._with_optional(
            {"jobFullName": job_full_name},
            buildNumber=build_number,
            displayName=display_name,
            description=description,
        )
        return await self._write_tool(
            "updateBuild",
            arguments,
            approval_id=approval_id,
            incident_id=incident_id,
            execution_capability=execution_capability,
        )

    async def rebuild_build(
        self,
        job_full_name: str,
        *,
        build_number: Optional[int] = None,
        approval_id: str,
        incident_id: str,
        execution_capability: str,
    ) -> Any:
        return await self._write_tool(
            "rebuildBuild",
            self._with_optional({"jobFullName": job_full_name}, buildNumber=build_number),
            approval_id=approval_id,
            incident_id=incident_id,
            execution_capability=execution_capability,
        )

    async def replay_build(
        self,
        job_full_name: str,
        main_script: str,
        *,
        build_number: Optional[int] = None,
        loaded_scripts: Optional[Mapping[str, str]] = None,
        approval_id: str,
        incident_id: str,
        execution_capability: str,
    ) -> Any:
        if not str(main_script or "").strip():
            raise ValueError("jenkins_replay_main_script_required")
        arguments = self._with_optional(
            {"jobFullName": job_full_name, "mainScript": main_script},
            buildNumber=build_number,
            loadedScripts=dict(loaded_scripts) if loaded_scripts is not None else None,
        )
        return await self._write_tool(
            "replayBuild",
            arguments,
            approval_id=approval_id,
            incident_id=incident_id,
            execution_capability=execution_capability,
        )
