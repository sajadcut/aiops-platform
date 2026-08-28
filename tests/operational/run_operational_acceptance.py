from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCENARIO_DIR = ROOT / "tests" / "operational" / "scenarios"
DEFAULT_REPORT_DIR = ROOT / "artifacts" / "operational-acceptance"
_ALLOWED_TEST_ENVS = {"staging", "stage", "lab", "test"}
_FORBIDDEN_TEST_ENVS = {"prod", "production", "live"}
_ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")
_FLOW_PLACEHOLDER_RE = re.compile(r'(:\s*)(\$\{[A-Z0-9_]+\})(?=\s*[,}])')

_NO_WRITE_SCENARIOS = {
    "PG-DEADLOCK", "PG-SLOW-QUERY", "FALSE-POSITIVE-ALERT", "CONFLICTING-TELEMETRY",
    "MISSING-TELEMETRY", "LLM-TIMEOUT", "LLM-UNSAFE-OUTPUT", "DUPLICATE-SIGNAL",
}
_EXECUTION_FAILURE_SCENARIOS = {"MCP-TIMEOUT", "REMEDIATION-FAILURE"}
_VERIFICATION_FAILURE_SCENARIOS = {"VERIFICATION-FAILURE"}


class OperationalAcceptanceError(RuntimeError):
    pass


class BlockedScenario(OperationalAcceptanceError):
    pass


@dataclass
class ScenarioResult:
    scenario_id: str
    status: str
    started_at: str
    finished_at: str
    correlation_id: str
    reason: str | None = None
    incident_id: str | None = None
    approval_id: str | None = None
    execution_id: str | None = None
    evidence_ids: list[str] | None = None
    rca_result: Any = None
    remediation_result: Any = None
    verification_result: Any = None
    monitoring: dict[str, Any] | None = None
    lifecycle: dict[str, Any] | None = None
    incident_context: dict[str, Any] | None = None
    audit_events: list[dict[str, Any]] | None = None
    injection_result: dict[str, Any] | None = None
    cleanup_result: dict[str, Any] | None = None


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def env(name: str, required: bool = True) -> str | None:
    value = os.getenv(name)
    if required and not value:
        raise BlockedScenario(f"missing_environment_variable:{name}")
    return value


def expand(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV_RE.sub(lambda match: env(match.group(1)) or "", value)
    if isinstance(value, list):
        return [expand(item) for item in value]
    if isinstance(value, dict):
        return {key: expand(item) for key, item in value.items()}
    return value


def _yaml_with_quoted_flow_placeholders(text: str) -> str:
    """Quote ${VAR} only when it is a bare value inside a YAML flow mapping."""
    return _FLOW_PLACEHOLDER_RE.sub(r'\1"\2"', text)


def load_scenarios() -> list[dict[str, Any]]:
    scenarios: list[dict[str, Any]] = []
    for path in sorted(SCENARIO_DIR.glob("*.yaml")):
        text = _yaml_with_quoted_flow_placeholders(path.read_text(encoding="utf-8"))
        try:
            raw = yaml.safe_load(text) or {}
        except yaml.YAMLError as exc:
            raise OperationalAcceptanceError(f"invalid_scenario_yaml:{path}:{exc}") from exc
        items = raw.get("scenarios", [])
        if not isinstance(items, list):
            raise OperationalAcceptanceError(f"invalid_scenario_file:{path}")
        for item in items:
            if not isinstance(item, dict):
                raise OperationalAcceptanceError(f"invalid_scenario_entry:{path}")
            scenario = dict(item)
            scenario["_source_file"] = str(path.relative_to(ROOT))
            scenarios.append(scenario)
    ids = [str(item.get("id") or "") for item in scenarios]
    if not ids or any(not item for item in ids) or len(ids) != len(set(ids)):
        raise OperationalAcceptanceError("scenario_ids_missing_or_duplicate")
    return scenarios


class SafetyGate:
    def __init__(self, environment: str):
        self.environment = environment.strip().lower()

    def validate(self, scenario: dict[str, Any]) -> None:
        configured_env = (os.getenv("AIOPS_TEST_ENV") or self.environment).strip().lower()
        if configured_env != self.environment:
            raise OperationalAcceptanceError("cli_environment_does_not_match_AIOPS_TEST_ENV")
        if self.environment in _FORBIDDEN_TEST_ENVS:
            raise OperationalAcceptanceError("operational_failure_injection_forbidden_in_production")
        if self.environment not in _ALLOWED_TEST_ENVS:
            raise OperationalAcceptanceError(f"unsupported_test_environment:{self.environment}")
        if not bool(scenario.get("destructive", True)):
            return
        if os.getenv("ALLOW_DESTRUCTIVE_TESTS", "").lower() != "true":
            raise BlockedScenario("ALLOW_DESTRUCTIVE_TESTS_must_equal_true")
        target = str(expand(scenario.get("target") or ""))
        if not target:
            raise BlockedScenario("scenario_target_missing")
        allowed_targets = {item.strip() for item in os.getenv("AIOPS_TEST_ALLOWED_TARGETS", "").split(",") if item.strip()}
        if target not in allowed_targets:
            raise BlockedScenario(f"target_not_allowlisted:{target}")
        if not scenario.get("rollback"):
            raise OperationalAcceptanceError("destructive_scenario_requires_rollback_contract")


class AIOpsClient:
    def __init__(self):
        base_url = (env("AIOPS_BASE_URL") or "").rstrip("/")
        headers: dict[str, str] = {"User-Agent": "aiops-operational-acceptance/1"}
        api_key = os.getenv("AIOPS_API_KEY")
        bearer = os.getenv("AIOPS_BEARER_TOKEN")
        if api_key:
            headers["X-API-Key"] = api_key
        elif bearer:
            headers["Authorization"] = f"Bearer {bearer}"
        else:
            raise BlockedScenario("AIOPS_API_KEY_or_AIOPS_BEARER_TOKEN_required")
        self.client = httpx.Client(
            base_url=base_url,
            headers=headers,
            timeout=15.0,
            verify=os.getenv("AIOPS_TLS_VERIFY", "true").lower() != "false",
        )

    def get(self, path: str, **kwargs: Any) -> Any:
        response = self.client.get(path, **kwargs)
        response.raise_for_status()
        return response.json()

    def post(self, path: str, **kwargs: Any) -> Any:
        response = self.client.post(path, **kwargs)
        response.raise_for_status()
        return response.json()

    def recent_incidents(self, started_at: datetime) -> list[dict[str, Any]]:
        payload = self.get("/api/v1/dashboard/incidents", params={"limit": 200})
        rows: list[dict[str, Any]] = []
        for item in payload.get("items", []):
            raw = item.get("created_at") or item.get("started_at")
            if not raw:
                continue
            try:
                created = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
            except ValueError:
                continue
            if created >= started_at:
                rows.append(item)
        return rows

    def find_new_incident(self, service: str, started_at: datetime) -> dict[str, Any] | None:
        return next((item for item in self.recent_incidents(started_at) if str(item.get("service") or "") == service), None)

    def lifecycle(self, incident_id: str) -> dict[str, Any]:
        return self.get(f"/api/v1/incidents/{incident_id}/lifecycle")

    def context(self, incident_id: str) -> dict[str, Any]:
        return self.get(f"/api/v1/incidents/{incident_id}/context")

    def evidence(self, incident_id: str) -> list[dict[str, Any]]:
        return self.get(f"/api/v1/incidents/{incident_id}/evidence", params={"limit": 500}).get("items", [])

    def approve_and_resume(self, incident_id: str, approval_id: str) -> None:
        self.post(f"/api/v1/approvals/{approval_id}/approve")
        self.post(f"/api/v1/workflow/e2e/{incident_id}/resume")

    def reject(self, approval_id: str) -> None:
        self.post(f"/api/v1/approvals/{approval_id}/reject", json={"reason": "operational acceptance expected rejection"})


class FaultInjectorClient:
    """Staging-only typed fault actuator. It cannot accept arbitrary commands."""

    def __init__(self):
        self.url = (env("AIOPS_FAULT_INJECTOR_URL") or "").rstrip("/")
        token = env("AIOPS_FAULT_INJECTOR_TOKEN") or ""
        self.headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        self.allowed_actions = {item.strip() for item in os.getenv("AIOPS_TEST_ALLOWED_FAULT_ACTIONS", "").split(",") if item.strip()}

    def _assert_allowed(self, action: str) -> None:
        if not action or action not in self.allowed_actions:
            raise BlockedScenario(f"fault_action_not_allowlisted:{action}")

    def inject(self, scenario: dict[str, Any], correlation_id: str) -> dict[str, Any]:
        spec = expand(scenario.get("injection") or {})
        action = str(spec.get("action") or "")
        self._assert_allowed(action)
        body = {
            "scenario_id": scenario["id"], "correlation_id": correlation_id,
            "environment": os.getenv("AIOPS_TEST_ENV"), "target": expand(scenario.get("target")),
            "action": action, "parameters": spec.get("parameters") or {},
        }
        response = httpx.post(f"{self.url}/inject", json=body, headers=self.headers, timeout=float(spec.get("timeout_seconds", 30)))
        response.raise_for_status()
        return response.json() if response.content else {}

    def cleanup(self, scenario: dict[str, Any], correlation_id: str) -> dict[str, Any]:
        rollback = expand(scenario.get("rollback") or {})
        action = str(rollback.get("action") or "")
        self._assert_allowed(action)
        body = {
            "scenario_id": scenario["id"], "correlation_id": correlation_id,
            "environment": os.getenv("AIOPS_TEST_ENV"), "target": expand(scenario.get("target")),
            "action": action, "parameters": rollback.get("parameters") or {},
        }
        response = httpx.post(f"{self.url}/cleanup", json=body, headers=self.headers, timeout=float(rollback.get("timeout_seconds", 60)))
        response.raise_for_status()
        return response.json() if response.content else {}


class MonitoringObserver:
    def observe(self, scenario: dict[str, Any]) -> dict[str, Any]:
        monitoring = scenario.get("monitoring") or {}
        results: dict[str, Any] = {}
        for source in monitoring.get("expected_sources") or []:
            method = getattr(self, f"_{source}", None)
            if method is None:
                raise BlockedScenario(f"unsupported_monitoring_source:{source}")
            result = method(monitoring)
            results[source] = result
            if not result.get("observed"):
                raise OperationalAcceptanceError(f"monitoring_signal_not_observed:{source}")
        return results

    def _prometheus(self, monitoring: dict[str, Any]) -> dict[str, Any]:
        base = (env("PROMETHEUS_URL") or "").rstrip("/")
        query = str(expand(monitoring.get("promql") or ""))
        if not query:
            raise BlockedScenario("promql_missing")
        response = httpx.get(f"{base}/api/v1/query", params={"query": query}, timeout=15.0)
        response.raise_for_status()
        rows = ((response.json().get("data") or {}).get("result") or [])
        return {"observed": bool(rows), "query": query, "sample_count": len(rows)}

    def _elasticsearch(self, monitoring: dict[str, Any]) -> dict[str, Any]:
        base = (env("ELASTICSEARCH_URL") or "").rstrip("/")
        query = str(expand(monitoring.get("elastic_query") or ""))
        if not query:
            raise BlockedScenario("elastic_query_missing")
        headers = {}
        if os.getenv("ELASTICSEARCH_API_KEY"):
            headers["Authorization"] = f"ApiKey {os.environ['ELASTICSEARCH_API_KEY']}"
        response = httpx.get(f"{base}/_search", params={"q": query, "size": 5}, headers=headers, timeout=15.0)
        response.raise_for_status()
        total = ((response.json().get("hits") or {}).get("total") or {})
        count = int(total.get("value", 0) if isinstance(total, dict) else total or 0)
        return {"observed": count > 0, "query": query, "hit_count": count}

    def _zabbix(self, monitoring: dict[str, Any]) -> dict[str, Any]:
        url = env("ZABBIX_API_URL") or ""
        token = env("ZABBIX_API_TOKEN") or ""
        search = str(expand(monitoring.get("zabbix_search") or ""))
        if not search:
            raise BlockedScenario("zabbix_search_missing")
        request = {
            "jsonrpc": "2.0", "method": "problem.get", "id": 1, "auth": token,
            "params": {"output": "extend", "recent": True, "sortfield": ["eventid"], "sortorder": "DESC", "limit": 100},
        }
        response = httpx.post(url, json=request, timeout=15.0)
        response.raise_for_status()
        payload = response.json()
        if payload.get("error"):
            raise OperationalAcceptanceError(f"zabbix_api_error:{payload['error']}")
        needle = search.lower()
        rows = [row for row in payload.get("result") or [] if needle in json.dumps(row, ensure_ascii=False).lower()]
        return {"observed": bool(rows), "search": search, "match_count": len(rows)}


def wait_for_monitoring(scenario: dict[str, Any]) -> dict[str, Any]:
    timeout = int((scenario.get("timing") or {}).get("monitor_timeout_seconds", 120))
    deadline = time.monotonic() + timeout
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return MonitoringObserver().observe(scenario)
        except BlockedScenario:
            raise
        except (OperationalAcceptanceError, httpx.HTTPError) as exc:
            last_error = exc
            time.sleep(5)
    if last_error:
        raise OperationalAcceptanceError(f"monitoring_timeout:{last_error}") from last_error
    raise OperationalAcceptanceError("monitoring_timeout")


def selected_agents(lifecycle: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    routing = lifecycle.get("routing") or {}
    for key in ("primary", "secondary", "selected_agents"):
        item = routing.get(key)
        if isinstance(item, str):
            values.add(item)
        elif isinstance(item, list):
            values.update(str(value) for value in item)
    for item in lifecycle.get("agents") or []:
        if isinstance(item, dict):
            name = item.get("agent") or item.get("agent_name") or item.get("name")
            if name:
                values.add(str(name))
    return values


def _is_resolved(context: dict[str, Any]) -> bool:
    return str(context.get("status") or "").lower() in {"resolved", "closed"}


def _verification_success(verification: Any) -> bool:
    text = json.dumps(verification or {}, ensure_ascii=False).lower()
    return bool(verification) and any(token in text for token in ('"success": true', '"passed": true', 'healthy', 'resolved', 'passed'))


def validate_lifecycle(
    scenario: dict[str, Any], lifecycle: dict[str, Any], context: dict[str, Any],
    evidence: list[dict[str, Any]], recent_incidents: list[dict[str, Any]],
) -> tuple[bool, str]:
    scenario_id = str(scenario["id"])
    expected = scenario.get("expected") or {}
    if not evidence:
        return False, "no_persisted_evidence"
    monitoring_sources = set((scenario.get("monitoring") or {}).get("expected_sources") or [])
    evidence_sources = {str(item.get("source") or "") for item in evidence}
    if monitoring_sources and not (monitoring_sources & evidence_sources):
        return False, f"no_monitoring_source_in_persisted_evidence:{sorted(monitoring_sources)}:{sorted(evidence_sources)}"
    expected_agents = {str(item) for item in expected.get("agents", [])}
    actual_agents = selected_agents(lifecycle)
    if expected_agents and not (expected_agents & actual_agents):
        return False, f"expected_agent_not_selected:{sorted(expected_agents)}:{sorted(actual_agents)}"
    if not lifecycle.get("decision"):
        return False, "decision_missing"

    execution = lifecycle.get("execution") or {}
    verification = lifecycle.get("verification") or {}
    approval = lifecycle.get("approval") or {}
    event_types = {str(item.get("event_type") or "") for item in lifecycle.get("audit") or [] if isinstance(item, dict)}
    required_audit = set(expected.get("audit_events", ["verification_completed"]))
    if not required_audit <= event_types:
        return False, f"audit_events_missing:{sorted(required_audit - event_types)}"

    if scenario_id == "APPROVAL-REJECTED":
        if str(approval.get("status") or "").lower() != "rejected":
            return False, f"approval_not_rejected:{approval.get('status')}"
        if execution and execution.get("success"):
            return False, "execution_occurred_after_rejection"
        if _is_resolved(context):
            return False, "incident_resolved_after_rejected_approval"
        return True, "rejected_approval_safely_blocked_execution"

    if scenario_id == "APPROVAL-EXPIRED":
        if str(approval.get("status") or "").lower() != "expired":
            return False, f"approval_not_expired:{approval.get('status')}"
        if execution and execution.get("success"):
            return False, "execution_occurred_after_expired_approval"
        if _is_resolved(context):
            return False, "incident_resolved_after_expired_approval"
        return True, "expired_approval_safely_blocked_execution"

    if scenario_id in _EXECUTION_FAILURE_SCENARIOS:
        if not execution or execution.get("success") is not False:
            return False, "expected_execution_failure_not_observed"
        if _verification_success(verification):
            return False, "failed_execution_was_followed_by_successful_verification"
        if _is_resolved(context):
            return False, "incident_resolved_after_execution_failure"
        return True, "execution_failure_failed_safe"

    if scenario_id in _VERIFICATION_FAILURE_SCENARIOS:
        if not execution or execution.get("success") is not True:
            return False, "expected_successful_execution_missing"
        if not verification or _verification_success(verification):
            return False, "expected_verification_failure_not_observed"
        if _is_resolved(context):
            return False, "incident_resolved_after_verification_failure"
        return True, "verification_failure_failed_safe"

    if scenario_id in _NO_WRITE_SCENARIOS or not expected.get("remediation_required", True):
        if execution and execution.get("success") is True:
            return False, "write_execution_occurred_in_no_write_scenario"
        if scenario_id == "DUPLICATE-SIGNAL":
            service = str(expand(scenario.get("service") or ""))
            matching = [item for item in recent_incidents if str(item.get("service") or "") == service]
            if len(matching) != 1:
                return False, f"duplicate_signal_created_multiple_incidents:{len(matching)}"
        return True, "analysis_or_safety_scenario_completed_without_unsafe_write"

    if expected.get("approval_required") and str(approval.get("status") or "").lower() not in {"approved", "consumed"}:
        return False, f"approval_not_completed:{approval.get('status')}"
    if not execution or execution.get("success") is not True:
        return False, "execution_not_successful"
    if not _verification_success(verification):
        return False, "verification_not_successful"
    if not _is_resolved(context):
        return False, f"incident_not_resolved_after_successful_verification:{context.get('status')}"

    if scenario_id == "CONCURRENT-INCIDENTS":
        second = str(expand((scenario.get("injection") or {}).get("parameters", {}).get("second_target") or ""))
        services = {str(item.get("service") or "") for item in recent_incidents}
        if second and not {str(expand(scenario.get("service") or "")), second} <= services:
            return False, f"concurrent_incidents_not_independently_created:{sorted(services)}"

    return True, "all_operational_acceptance_invariants_satisfied"


def run_one(scenario: dict[str, Any], environment: str, report_dir: Path) -> ScenarioResult:
    correlation_id = f"oat-{scenario['id'].lower()}-{uuid4()}"
    started = datetime.now(timezone.utc)
    result = ScenarioResult(str(scenario["id"]), "FAIL", started.isoformat(), started.isoformat(), correlation_id)
    injected = False
    injector: FaultInjectorClient | None = None
    try:
        SafetyGate(environment).validate(scenario)
        service = str(expand(scenario.get("service") or ""))
        if not service:
            raise BlockedScenario("scenario_service_missing")
        aiops = AIOpsClient()
        if scenario.get("destructive", True):
            injector = FaultInjectorClient()
            result.injection_result = injector.inject(scenario, correlation_id)
            injected = True

        settle = int((scenario.get("timing") or {}).get("monitor_settle_seconds", 5))
        if settle:
            time.sleep(settle)
        result.monitoring = wait_for_monitoring(scenario)

        incident_deadline = time.monotonic() + int((scenario.get("timing") or {}).get("incident_timeout_seconds", 240))
        incident = None
        while time.monotonic() < incident_deadline:
            incident = aiops.find_new_incident(service, started)
            if incident:
                break
            time.sleep(5)
        if not incident:
            raise OperationalAcceptanceError("incident_not_created_from_real_monitoring_signal")
        result.incident_id = str(incident["id"])

        terminal_deadline = time.monotonic() + int((scenario.get("timing") or {}).get("terminal_timeout_seconds", 360))
        lifecycle: dict[str, Any] = {}
        approval_action_done = False
        while time.monotonic() < terminal_deadline:
            lifecycle = aiops.lifecycle(result.incident_id)
            approval = lifecycle.get("approval") or {}
            if approval.get("approval_id"):
                result.approval_id = str(approval["approval_id"])
            approval_status = str(approval.get("status") or "").lower()

            if approval_status == "pending" and result.approval_id and not approval_action_done:
                if scenario["id"] == "APPROVAL-REJECTED":
                    aiops.reject(result.approval_id)
                    approval_action_done = True
                    time.sleep(2)
                    continue
                if scenario["id"] != "APPROVAL-EXPIRED" and (scenario.get("expected") or {}).get("approval_required") and os.getenv("AIOPS_TEST_AUTO_APPROVE", "").lower() == "true":
                    aiops.approve_and_resume(result.incident_id, result.approval_id)
                    approval_action_done = True
                    time.sleep(2)
                    continue

            if scenario["id"] == "APPROVAL-EXPIRED" and approval_status == "expired":
                break
            if scenario["id"] == "APPROVAL-REJECTED" and approval_status == "rejected":
                break
            if lifecycle.get("verification") or lifecycle.get("terminal_reason"):
                break
            time.sleep(5)

        evidence = aiops.evidence(result.incident_id)
        context = aiops.context(result.incident_id)
        recent_incidents = aiops.recent_incidents(started)
        result.evidence_ids = [str(item.get("id")) for item in evidence if item.get("id")]
        result.lifecycle = lifecycle
        result.incident_context = context
        result.audit_events = lifecycle.get("audit") or []
        result.rca_result = lifecycle.get("evaluation") or lifecycle.get("final_plan")
        result.remediation_result = lifecycle.get("execution")
        result.verification_result = lifecycle.get("verification")
        execution = lifecycle.get("execution") or {}
        if isinstance(execution, dict):
            result.execution_id = execution.get("execution_id")
        passed, reason = validate_lifecycle(scenario, lifecycle, context, evidence, recent_incidents)
        result.status = "PASS" if passed else "FAIL"
        result.reason = reason
    except BlockedScenario as exc:
        result.status = "BLOCKED"
        result.reason = str(exc)
    except Exception as exc:
        result.status = "FAIL"
        result.reason = f"{type(exc).__name__}:{exc}"
    finally:
        if injected and injector is not None:
            try:
                result.cleanup_result = injector.cleanup(scenario, correlation_id)
            except Exception as exc:
                result.status = "FAIL"
                result.reason = f"cleanup_failed:{type(exc).__name__}:{exc}"
        result.finished_at = utcnow()
        report_dir.mkdir(parents=True, exist_ok=True)
        (report_dir / f"{scenario['id']}.json").write_text(
            json.dumps(asdict(result), ensure_ascii=False, indent=2, default=str) + "\n",
            encoding="utf-8",
        )
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Run production-like AIOps operational acceptance scenarios")
    parser.add_argument("--environment", required=True)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true")
    group.add_argument("--scenario")
    parser.add_argument("--report-dir", default=str(DEFAULT_REPORT_DIR))
    args = parser.parse_args()

    scenarios = load_scenarios()
    if args.scenario:
        scenarios = [item for item in scenarios if item["id"] == args.scenario]
        if not scenarios:
            print(f"Unknown scenario: {args.scenario}", file=sys.stderr)
            return 2
    report_dir = Path(args.report_dir)
    results = [run_one(item, args.environment, report_dir) for item in scenarios]
    summary = {
        "environment": args.environment,
        "generated_at": utcnow(),
        "results": [asdict(item) for item in results],
        "counts": {status: sum(1 for item in results if item.status == status) for status in ("PASS", "FAIL", "BLOCKED", "PARTIAL", "NOT RUN")},
    }
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")
    for item in results:
        print(f"{item.scenario_id}: {item.status} - {item.reason or ''}")
    return 0 if results and all(item.status == "PASS" for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
