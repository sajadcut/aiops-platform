from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from apps.runbook_service.registry import RunbookRegistry


class RemediationPlanner:
    """Deterministically bind live operational Evidence to a governed write request.

    The planner never converts free-form LLM/RCA prose into commands. It may only
    emit an execution request when a registered runbook explicitly authorizes the
    tool/action and Live Evidence independently proves the VM target, service and
    unhealthy service state. The Decision/Approval/Capability/Execution boundaries
    remain authoritative after planning.
    """

    VM_SERVICE_RUNBOOK = "vm-service-recovery"
    SIGNAL_SOURCES = {"zabbix", "prometheus", "elasticsearch", "kubernetes"}
    START_SERVICE_STATES = {
        "inactive", "dead", "stopped", "down", "not-running", "not_running",
    }
    RESTART_SERVICE_STATES = {"failed"}
    UNHEALTHY_SERVICE_STATES = START_SERVICE_STATES | RESTART_SERVICE_STATES
    HEALTHY_SERVICE_STATES = {"active", "running", "up"}

    @classmethod
    def plan(cls, state: Dict[str, Any]) -> Dict[str, Any]:
        base: Dict[str, Any] = {
            "status": "not_planned",
            "reason": "no_governed_remediation_match",
            "live_identity_verified": False,
            "execution_request": None,
            "evidence_refs": [],
        }

        evaluation = dict(state.get("evaluation") or {})
        if evaluation.get("approved_for_decision") is not True:
            return {**base, "reason": "evaluation_not_approved"}

        context = dict(state.get("context") or {})
        trigger_signal = context.get("trigger_signal")
        if not isinstance(trigger_signal, dict):
            return {**base, "reason": "automatic_planning_requires_source_trigger"}
        source = str(trigger_signal.get("source") or "").strip().lower()
        if source not in cls.SIGNAL_SOURCES:
            return {**base, "reason": "trigger_source_not_auto_remediation_eligible"}

        policy = cls._load_vm_service_policy()
        if policy is None:
            return {**base, "reason": "vm_service_recovery_runbook_unavailable"}

        evidence = cls._evidence_items(state)
        service_bindings = cls._unhealthy_service_bindings(evidence)
        if not service_bindings:
            return {**base, "reason": "no_live_inactive_service_evidence"}
        if len(service_bindings) != 1:
            return {**base, "reason": "ambiguous_live_service_binding"}

        (target, service), binding_refs = next(iter(service_bindings.items()))
        states, status_refs = cls._service_states(evidence, target=target, service=service)
        action, action_reason = cls._recovery_action(states)
        status_refs = cls._dedupe(binding_refs + status_refs)
        if action is None:
            return {
                **base,
                "reason": action_reason,
                "target": target,
                "service": service,
                "evidence_refs": status_refs,
            }

        config_ok, config_refs, config_reason = cls._configuration_precondition(
            evidence, target=target, service=service
        )
        if not config_ok:
            return {
                **base,
                "reason": config_reason,
                "target": target,
                "service": service,
                "evidence_refs": cls._dedupe(status_refs + config_refs),
            }

        port, port_refs, port_reason = cls._target_port(evidence, target=target, service=service)
        if port_reason:
            return {
                **base,
                "reason": port_reason,
                "target": target,
                "service": service,
                "evidence_refs": cls._dedupe(status_refs + config_refs + port_refs),
            }

        tool_name = str((policy.get("execution") or {}).get("tool") or "")
        allowed_actions = {
            str(value).strip()
            for value in (policy.get("execution") or {}).get("allowed_actions", [])
            if str(value).strip()
        }
        step_actions = {
            str(step.get("action") or "").strip()
            for step in policy.get("steps", [])
            if isinstance(step, dict)
        }
        if tool_name != "ssh_vm" or action not in allowed_actions or action not in step_actions:
            return {**base, "reason": "runbook_execution_contract_mismatch"}
        if (policy.get("execution") or {}).get("auto_plan_from_signals") is not True:
            return {**base, "reason": "runbook_automatic_planning_disabled"}

        parameters: Dict[str, Any] = {"service": service}
        if port is not None:
            parameters["target_port"] = port

        request = {
            "tool_name": tool_name,
            "action": action,
            "target": target,
            "parameters": parameters,
            "timeout": int(policy.get("timeout") or 30),
            "agent_name": "remediation_planner",
            "incident_id": state.get("incident_id"),
            "runbook_id": str(policy.get("id") or cls.VM_SERVICE_RUNBOOK),
            "runbook_version": str(policy.get("version") or ""),
            "rollback": False,
        }
        refs = cls._dedupe(status_refs + config_refs + port_refs)
        return {
            "status": "planned",
            "reason": (
                "live_vm_service_stopped_matches_governed_start"
                if action == "start_service"
                else "live_vm_service_failed_matches_governed_restart"
            ),
            "live_identity_verified": True,
            "source": source,
            "target": target,
            "service": service,
            "service_states": sorted(states),
            "target_port": port,
            "runbook_id": request["runbook_id"],
            "runbook_version": request["runbook_version"],
            "evidence_refs": refs,
            "execution_request": request,
        }

    @classmethod
    def revalidate_execution(
        cls, execution_request: Dict[str, Any], evidence: Iterable[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Fail closed if the approved write is stale immediately before execution."""
        action = str(execution_request.get("action") or "")
        if str(execution_request.get("tool_name") or "") != "ssh_vm" or action not in {"start_service", "restart_service"}:
            return {"safe_to_execute": False, "reason": "unsupported_execution_binding", "evidence_refs": []}
        if str(execution_request.get("runbook_id") or "") != cls.VM_SERVICE_RUNBOOK:
            return {"safe_to_execute": False, "reason": "unrecognized_remediation_runbook", "evidence_refs": []}

        target = str(execution_request.get("target") or "").strip()
        parameters = dict(execution_request.get("parameters") or {})
        service = str(parameters.get("service") or "").strip()
        if not target or not service:
            return {"safe_to_execute": False, "reason": "execution_binding_incomplete", "evidence_refs": []}

        states, status_refs = cls._service_states(evidence, target=target, service=service)
        if not states:
            return {"safe_to_execute": False, "reason": "fresh_service_status_missing", "evidence_refs": status_refs}
        if states & cls.HEALTHY_SERVICE_STATES:
            return {"safe_to_execute": False, "reason": "service_no_longer_unhealthy", "evidence_refs": status_refs}
        fresh_action, action_reason = cls._recovery_action(states)
        if fresh_action is None:
            return {"safe_to_execute": False, "reason": action_reason, "evidence_refs": status_refs}
        if fresh_action != action:
            return {"safe_to_execute": False, "reason": "fresh_service_recovery_action_changed", "evidence_refs": status_refs}

        config_ok, config_refs, config_reason = cls._configuration_precondition(
            evidence, target=target, service=service
        )
        refs = cls._dedupe(status_refs + config_refs)
        if not config_ok:
            return {"safe_to_execute": False, "reason": config_reason, "evidence_refs": refs}
        return {
            "safe_to_execute": True,
            "reason": "fresh_execution_preconditions_satisfied",
            "action": action,
            "target": target,
            "service": service,
            "evidence_refs": refs,
        }

    @classmethod
    def _recovery_action(cls, states: set[str]) -> Tuple[Optional[str], str]:
        normalized = {str(state).strip().lower() for state in states if str(state).strip()}
        if not normalized:
            return None, "service_state_missing"
        if normalized & cls.HEALTHY_SERVICE_STATES:
            return None, "service_state_conflict_or_recovered"
        if normalized & cls.RESTART_SERVICE_STATES:
            if not normalized.issubset(cls.RESTART_SERVICE_STATES):
                return None, "ambiguous_live_service_state"
            return "restart_service", "service_failed"
        if normalized.issubset(cls.START_SERVICE_STATES):
            return "start_service", "service_stopped"
        return None, "fresh_service_status_inconclusive"

    @classmethod
    def _load_vm_service_policy(cls) -> Optional[Dict[str, Any]]:
        try:
            root = Path(__file__).resolve().parents[2] / "runbooks"
            registry = RunbookRegistry(str(root))
            runbook = registry.get(cls.VM_SERVICE_RUNBOOK)
            validation = registry.validate(cls.VM_SERVICE_RUNBOOK, {})
        except (KeyError, OSError, TypeError, ValueError):
            return None
        if not validation.get("valid"):
            return None
        return runbook

    @staticmethod
    def _evidence_items(state: Dict[str, Any]) -> List[Dict[str, Any]]:
        context = dict(state.get("context") or {})
        candidates = context.get("evidence")
        if not isinstance(candidates, list):
            live = state.get("live_evidence") or context.get("live_evidence") or {}
            candidates = live.get("evidence", []) if isinstance(live, dict) else []
        return [item for item in candidates if isinstance(item, dict)]

    @classmethod
    def _service_states(
        cls, evidence: Iterable[Dict[str, Any]], *, target: str, service: str
    ) -> Tuple[set[str], List[str]]:
        states: set[str] = set()
        refs: List[str] = []
        for item in evidence:
            if str(item.get("source") or "").strip().lower() != "vm_mcp":
                continue
            raw = item.get("raw_data") or {}
            if not isinstance(raw, dict) or str(raw.get("diagnostic") or "").strip().lower() != "service_status":
                continue
            if str(raw.get("target") or "").strip() != target or str(raw.get("service") or "").strip() != service:
                continue
            value = str(
                raw.get("active_state")
                or raw.get("status")
                or raw.get("state")
                or raw.get("sub_state")
                or ""
            ).strip().lower()
            if value:
                states.add(value)
            ref = str(item.get("reference") or "").strip()
            if ref:
                refs.append(ref)
        return states, cls._dedupe(refs)

    @classmethod
    def _unhealthy_service_bindings(
        cls, evidence: Iterable[Dict[str, Any]]
    ) -> Dict[Tuple[str, str], List[str]]:
        bindings: Dict[Tuple[str, str], List[str]] = {}
        for item in evidence:
            if str(item.get("source") or "").strip().lower() != "vm_mcp":
                continue
            raw = item.get("raw_data") or {}
            if not isinstance(raw, dict) or str(raw.get("diagnostic") or "").strip().lower() != "service_status":
                continue
            target = str(raw.get("target") or "").strip()
            service = str(raw.get("service") or "").strip()
            if not target or not service:
                continue
            state = str(
                raw.get("active_state")
                or raw.get("status")
                or raw.get("state")
                or raw.get("sub_state")
                or ""
            ).strip().lower()
            if state not in cls.UNHEALTHY_SERVICE_STATES:
                continue
            ref = str(item.get("reference") or "").strip()
            bindings.setdefault((target, service), [])
            if ref:
                bindings[(target, service)].append(ref)
        return bindings

    @staticmethod
    def _configuration_precondition(
        evidence: Iterable[Dict[str, Any]], *, target: str, service: str
    ) -> Tuple[bool, List[str], str]:
        matching: List[Tuple[Dict[str, Any], str]] = []
        for item in evidence:
            if str(item.get("source") or "").strip().lower() != "vm_mcp":
                continue
            raw = item.get("raw_data") or {}
            if not isinstance(raw, dict) or str(raw.get("diagnostic") or "").strip().lower() != "config_validate":
                continue
            if str(raw.get("target") or "").strip() != target or str(raw.get("service") or "").strip() != service:
                continue
            matching.append((raw, str(item.get("reference") or "").strip()))

        refs = [ref for _, ref in matching if ref]
        if not matching:
            return False, refs, "configuration_validation_evidence_missing"

        for raw, _ in matching:
            if raw.get("supported") is True and raw.get("valid") is not True:
                return False, refs, "service_configuration_invalid"

        if any(raw.get("valid") is True or raw.get("supported") is False for raw, _ in matching):
            return True, refs, "configuration_precondition_satisfied"
        return False, refs, "configuration_validation_inconclusive"

    @staticmethod
    def _target_port(
        evidence: Iterable[Dict[str, Any]], *, target: str, service: str
    ) -> Tuple[Optional[int], List[str], Optional[str]]:
        ports: set[int] = set()
        refs: List[str] = []
        for item in evidence:
            if str(item.get("source") or "").strip().lower() != "vm_mcp":
                continue
            raw = item.get("raw_data") or {}
            if not isinstance(raw, dict):
                continue
            diagnostic = str(raw.get("diagnostic") or "").strip().lower()
            if diagnostic not in {"port_listener_status", "tcp_check"}:
                continue
            if str(raw.get("target") or "").strip() != target:
                continue
            raw_service = str(raw.get("service") or "").strip()
            if raw_service and raw_service != service:
                continue
            raw_port = raw.get("target_port") or raw.get("port")
            try:
                port = int(raw_port)
            except (TypeError, ValueError):
                continue
            if 1 <= port <= 65535:
                ports.add(port)
                ref = str(item.get("reference") or "").strip()
                if ref:
                    refs.append(ref)
        if len(ports) > 1:
            return None, refs, "ambiguous_live_target_port"
        return (next(iter(ports)) if ports else None), refs, None

    @staticmethod
    def _dedupe(values: Iterable[str]) -> List[str]:
        return list(dict.fromkeys(str(value) for value in values if str(value).strip()))