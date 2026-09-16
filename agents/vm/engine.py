from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from agents.infrastructure.engine import build_infrastructure_analysis


def _raw(item: Mapping[str, Any]) -> Mapping[str, Any]:
    value = item.get("raw_data")
    return value if isinstance(value, Mapping) else {}


def _eid(item: Mapping[str, Any], index: int) -> str:
    value = item.get("evidence_id") or item.get("id") or item.get("reference") or item.get("source_id")
    return str(value) if value not in (None, "") else f"anonymous:{index}"


def _parse_time(value: Any) -> Optional[datetime]:
    if value in (None, ""):
        return None
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)
    except (TypeError, ValueError, OverflowError):
        return None


def _timestamp(item: Mapping[str, Any]) -> Optional[datetime]:
    raw = _raw(item)
    for value in (item.get("observed_at"), item.get("timestamp"), item.get("created_at"), raw.get("timestamp"), raw.get("@timestamp")):
        parsed = _parse_time(value)
        if parsed:
            return parsed
    return None


def _scalar(item: Mapping[str, Any], *keys: str) -> Optional[str]:
    raw = _raw(item)
    for source in (item, raw):
        for key in keys:
            value = source.get(key)
            if value not in (None, "") and not isinstance(value, (Mapping, list, tuple)):
                return str(value)[:320]
    return None


def _numeric(item: Mapping[str, Any], *keys: str) -> Optional[float]:
    raw = _raw(item)
    for source in (item, raw):
        for key in keys:
            value = source.get(key)
            if value in (None, "") or isinstance(value, bool):
                continue
            try:
                if isinstance(value, str):
                    value = value.strip().rstrip("%").replace(",", "")
                return float(value)
            except (TypeError, ValueError):
                continue
    return None


def _bool(item: Mapping[str, Any], *keys: str) -> Optional[bool]:
    raw = _raw(item)
    for source in (item, raw):
        for key in keys:
            value = source.get(key)
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                normalized = value.strip().lower()
                if normalized in {"true", "yes", "1", "running", "active", "listening", "reachable"}:
                    return True
                if normalized in {"false", "no", "0", "stopped", "inactive", "dead", "unreachable"}:
                    return False
    return None


def _diagnostic(item: Mapping[str, Any]) -> str:
    return str(_raw(item).get("diagnostic") or item.get("diagnostic") or "").strip().lower()


def _incident_start(context: Mapping[str, Any]) -> Optional[datetime]:
    sources = [context]
    summary = context.get("summary") if isinstance(context.get("summary"), Mapping) else None
    if summary:
        sources.append(summary)
    for source in sources:
        for key in ("incident_start", "started_at", "start_time", "created_at"):
            parsed = _parse_time(source.get(key))
            if parsed:
                return parsed
    return None


def _platform(items: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    linux = 0
    windows = 0
    ids: List[str] = []
    for index, item in enumerate(items):
        raw = _raw(item)
        values = " ".join(str(raw.get(key) or item.get(key) or "") for key in ("os", "platform", "os_family", "service_manager", "source"))
        lowered = values.lower()
        diagnostic = _diagnostic(item)
        if any(token in lowered for token in ("linux", "ubuntu", "debian", "rhel", "centos", "rocky", "systemd")) or diagnostic.startswith("systemd"):
            linux += 1
            ids.append(_eid(item, index))
        if any(token in lowered for token in ("windows", "win32", "win64", "service control manager", "scm", "powershell")):
            windows += 1
            ids.append(_eid(item, index))
    if linux and not windows:
        name = "linux"
    elif windows and not linux:
        name = "windows"
    elif linux and windows:
        name = "mixed_or_conflicting"
    else:
        name = "unknown"
    return {"platform": name, "linux_signals": linux, "windows_signals": windows, "evidence_ids": list(dict.fromkeys(ids))[:20]}


def _process_row(item: Mapping[str, Any], index: int) -> Optional[Dict[str, Any]]:
    raw = _raw(item)
    diagnostic = _diagnostic(item)
    process = raw.get("process") if isinstance(raw.get("process"), Mapping) else {}
    parent = process.get("parent") if isinstance(process.get("parent"), Mapping) else {}
    relevant = diagnostic in {"process_status", "process_snapshot", "process_info", "process_tree", "process_list"}
    pid = process.get("pid") or raw.get("pid") or item.get("pid")
    name = process.get("name") or raw.get("process_name") or raw.get("name")
    if not relevant and pid in (None, "") and name in (None, ""):
        return None
    ppid = process.get("ppid") or parent.get("pid") or raw.get("ppid") or raw.get("parent_pid")
    running = _bool(item, "running", "alive", "is_running")
    restart_count = _numeric(item, "restart_count", "restarts", "restart_total")
    return {
        "evidence_id": _eid(item, index),
        "timestamp": _timestamp(item).isoformat() if _timestamp(item) else None,
        "name": str(name)[:180] if name not in (None, "") else _scalar(item, "process"),
        "pid": str(pid) if pid not in (None, "") else None,
        "parent_pid": str(ppid) if ppid not in (None, "") else None,
        "parent_name": str(parent.get("name") or raw.get("parent_name") or raw.get("parent_process") or "")[:180] or None,
        "running": running,
        "cpu_percent": _numeric(item, "cpu_percent", "cpu_pct", "cpu_usage", "cpu"),
        "memory_percent": _numeric(item, "memory_percent", "memory_pct", "mem_percent"),
        "rss_bytes": _numeric(item, "rss_bytes", "rss", "resident_bytes"),
        "restart_count": int(restart_count) if restart_count is not None and restart_count >= 0 else None,
        "fd_count": _numeric(item, "fd_count", "open_fds", "file_descriptors"),
        "socket_count": _numeric(item, "socket_count", "sockets", "open_sockets"),
        "start_timestamp": _scalar(item, "start_timestamp", "started_at", "start_time"),
        "host": _scalar(item, "host", "hostname", "instance", "node"),
    }


def _process_analysis(items: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    rows = [row for index, item in enumerate(items) if (row := _process_row(item, index)) is not None]
    by_key: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for row in rows:
        if row.get("pid"):
            by_key[(str(row.get("host") or "unknown"), str(row["pid"]))] = row
    edges: List[Dict[str, Any]] = []
    unresolved: List[Dict[str, Any]] = []
    for row in rows:
        if not row.get("parent_pid"):
            continue
        parent = by_key.get((str(row.get("host") or "unknown"), str(row["parent_pid"])))
        if parent:
            edges.append({
                "host": row.get("host"), "parent_pid": parent.get("pid"), "parent_name": parent.get("name"),
                "child_pid": row.get("pid"), "child_name": row.get("name"),
                "evidence_ids": list(dict.fromkeys([str(parent["evidence_id"]), str(row["evidence_id"])])),
            })
        else:
            unresolved.append({"host": row.get("host"), "child_pid": row.get("pid"), "parent_pid": row.get("parent_pid"), "evidence_id": row.get("evidence_id")})
    absent = [row for row in rows if row.get("running") is False]
    restarty = [row for row in rows if isinstance(row.get("restart_count"), int) and row["restart_count"] >= 3]
    fd_pressure = [row for row in rows if row.get("fd_count") is not None and float(row["fd_count"]) >= 1024]
    return {
        "processes": rows[:80],
        "process_count": len(rows),
        "parent_child_edges": edges[:80],
        "unresolved_parent_references": unresolved[:30],
        "absent_processes": absent[:20],
        "restart_behavior_candidates": restarty[:20],
        "fd_pressure_candidates": fd_pressure[:20],
        "policy": "process absence/resource pressure is an observation; cause requires service/log/kernel correlation",
    }


def _failed_dependencies(raw: Mapping[str, Any]) -> List[str]:
    value = raw.get("failed_dependencies") or raw.get("failed_units") or raw.get("dependency_failures") or []
    if isinstance(value, str):
        return [value[:240]] if value.strip() else []
    if isinstance(value, (list, tuple)):
        return [str(item)[:240] for item in value[:20] if item not in (None, "")]
    return []


def _service_row(item: Mapping[str, Any], index: int) -> Optional[Dict[str, Any]]:
    raw = _raw(item)
    diagnostic = _diagnostic(item)
    fields_present = any(key in raw for key in ("load_state", "active_state", "sub_state", "result", "main_pid", "exit_status", "restart_count", "n_restarts", "failed_dependencies"))
    if diagnostic not in {"service_status", "systemd_status", "systemd_service", "service_state"} and not fields_present:
        return None
    restart_count = _numeric(item, "restart_count", "n_restarts", "restarts")
    exit_status = _numeric(item, "exit_status", "exec_main_status", "status")
    return {
        "evidence_id": _eid(item, index),
        "timestamp": _timestamp(item).isoformat() if _timestamp(item) else None,
        "service": _scalar(item, "service", "unit", "service_name", "name"),
        "load_state": (_scalar(item, "load_state") or "unknown").lower(),
        "active_state": (_scalar(item, "active_state", "state") or "unknown").lower(),
        "sub_state": (_scalar(item, "sub_state") or "unknown").lower(),
        "result": (_scalar(item, "result", "service_result") or "unknown").lower(),
        "main_pid": _scalar(item, "main_pid", "pid", "exec_main_pid"),
        "exit_status": int(exit_status) if exit_status is not None else None,
        "restart_count": int(restart_count) if restart_count is not None and restart_count >= 0 else None,
        "start_timestamp": _scalar(item, "start_timestamp", "active_enter_timestamp", "started_at", "start_time"),
        "failed_dependencies": _failed_dependencies(raw),
        "host": _scalar(item, "host", "hostname", "instance", "node"),
    }


def _service_analysis(items: Sequence[Mapping[str, Any]], service_name: Optional[str]) -> Dict[str, Any]:
    rows = [row for index, item in enumerate(items) if (row := _service_row(item, index)) is not None]
    if service_name:
        named = [row for row in rows if not row.get("service") or str(row.get("service")) == str(service_name)]
        if named:
            rows = named
    failed = [row for row in rows if row.get("active_state") == "failed" or row.get("sub_state") == "failed" or row.get("result") not in {"unknown", "success", "done"}]
    inactive = [row for row in rows if row.get("active_state") == "inactive" or row.get("sub_state") == "dead"]
    dependency_failures = [row for row in rows if row.get("failed_dependencies")]
    restart_loop = [row for row in rows if isinstance(row.get("restart_count"), int) and row["restart_count"] >= 3]
    return {
        "service_states": rows[:40],
        "failed_states": failed[:20],
        "inactive_states": inactive[:20],
        "failed_dependency_states": dependency_failures[:20],
        "restart_loop_candidates": restart_loop[:20],
        "manual_stop_policy": "inactive/dead or exit_status=0 does not prove a manual stop; explicit journal/audit actor+action evidence is required",
    }


def _boot_analysis(items: Sequence[Mapping[str, Any]], incident_start: Optional[datetime]) -> Dict[str, Any]:
    boot_time: Optional[str] = None
    uptime_seconds: Optional[float] = None
    reboot_events: List[Dict[str, Any]] = []
    for index, item in enumerate(items):
        raw = _raw(item)
        diagnostic = _diagnostic(item)
        if boot_time is None:
            boot_time = _scalar(item, "boot_time", "boot_timestamp", "system_boot_time")
        if uptime_seconds is None:
            uptime_seconds = _numeric(item, "uptime_seconds", "uptime", "system_uptime")
        if diagnostic in {"reboot_history", "reboot_event", "boot_event"} or any(key in raw for key in ("reboot_reason", "shutdown_reason", "boot_id")):
            stamp = _timestamp(item)
            reboot_events.append({
                "evidence_id": _eid(item, index),
                "timestamp": stamp.isoformat() if stamp else None,
                "reason": _scalar(item, "reboot_reason", "shutdown_reason", "reason"),
                "boot_id": _scalar(item, "boot_id"),
                "incident_offset_seconds": round((stamp - incident_start).total_seconds(), 3) if stamp and incident_start else None,
            })
    reboot_events.sort(key=lambda row: row.get("timestamp") or "")
    return {"boot_time": boot_time, "uptime_seconds": uptime_seconds, "reboot_events": reboot_events[:40]}


def _causal_findings(host: Mapping[str, Any], process: Mapping[str, Any], service: Mapping[str, Any], boot: Mapping[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    matrix = host.get("health_matrix") if isinstance(host.get("health_matrix"), Mapping) else {}
    cpu = matrix.get("cpu") if isinstance(matrix.get("cpu"), Mapping) else {}
    disk = matrix.get("disk") if isinstance(matrix.get("disk"), Mapping) else {}
    memory = matrix.get("memory") if isinstance(matrix.get("memory"), Mapping) else {}
    if disk.get("status") in {"saturated", "pressure"} and cpu.get("status") in {"iowait_pressure", "saturated"}:
        findings.append({"code": "storage_pressure_visible_as_guest_cpu_wait", "evidence_ids": list(dict.fromkeys((disk.get("evidence_ids") or []) + (cpu.get("evidence_ids") or []))), "handoff": "storage"})
    if memory.get("status") in {"saturated", "pressure", "oom"}:
        findings.append({"code": "guest_memory_pressure", "evidence_ids": memory.get("evidence_ids") or [], "handoff": "infrastructure"})
    if service.get("failed_dependency_states"):
        ids = [str(row.get("evidence_id")) for row in service["failed_dependency_states"]]
        findings.append({"code": "systemd_failed_dependency", "evidence_ids": ids, "handoff": "dependency"})
    if service.get("restart_loop_candidates"):
        ids = [str(row.get("evidence_id")) for row in service["restart_loop_candidates"]]
        findings.append({"code": "service_restart_loop", "evidence_ids": ids})
    if process.get("fd_pressure_candidates"):
        ids = [str(row.get("evidence_id")) for row in process["fd_pressure_candidates"]]
        findings.append({"code": "process_fd_pressure", "evidence_ids": ids})
    if boot.get("reboot_events"):
        near = [row for row in boot["reboot_events"] if row.get("incident_offset_seconds") is not None and abs(float(row["incident_offset_seconds"])) <= 900]
        if near:
            findings.append({"code": "reboot_near_incident", "evidence_ids": [str(row["evidence_id"]) for row in near]})
    return findings[:16]


def build_vm_guest_analysis(
    evidence: Iterable[Mapping[str, Any]], *, service_name: Optional[str] = None, context: Optional[Mapping[str, Any]] = None
) -> Dict[str, Any]:
    items = [item for item in evidence if isinstance(item, Mapping)]
    ctx = context if isinstance(context, Mapping) else {}
    incident_start = _incident_start(ctx)
    host = build_infrastructure_analysis(items, service_name=service_name, context=ctx)
    process = _process_analysis(items)
    service = _service_analysis(items, service_name)
    boot = _boot_analysis(items, incident_start)
    causal = _causal_findings(host, process, service, boot)
    handoffs: List[str] = []
    for target in list(host.get("handoff_candidates") or []) + [row.get("handoff") for row in causal]:
        target = str(target or "")
        if target and target != "vm" and target not in handoffs:
            handoffs.append(target)
    gaps: List[Dict[str, Any]] = []
    if not host.get("metric_kinds"):
        gaps.append({"evidence": "guest host metrics: CPU/load/iowait/steal, memory/swap/PSI, disk/inode/I/O", "information_gain": 0.97})
    if process.get("process_count") == 0:
        gaps.append({"evidence": "process snapshot with PID/PPID CPU memory FD sockets and restart state", "information_gain": 0.94})
    if not service.get("service_states"):
        gaps.append({"evidence": "systemd service state: load/active/sub/result/main PID/exit/restarts/start/failed dependencies", "information_gain": 0.96})
    if not boot.get("boot_time") and not boot.get("reboot_events"):
        gaps.append({"evidence": "boot time and reboot history", "information_gain": 0.78})
    gaps.sort(key=lambda row: float(row["information_gain"]), reverse=True)
    return {
        "policy": "guest diagnosis is evidence-driven; host utilization alone is not saturation; inactive service alone is not proof of manual stop",
        "service": service_name,
        "platform_detection": _platform(items),
        "incident_start": incident_start.isoformat() if incident_start else None,
        "host_analysis": host,
        "process_analysis": process,
        "service_analysis": service,
        "boot_reboot_analysis": boot,
        "causal_findings": causal,
        "handoff_candidates": handoffs[:8],
        "evidence_gaps": gaps[:8],
        "next_best_evidence": gaps[:6],
        "analysis_stages": ["platform", "host_use", "process", "service_manager", "boot_reboot", "causal_synthesis"],
    }
