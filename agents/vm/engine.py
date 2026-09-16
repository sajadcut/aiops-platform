from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

from agents.infrastructure.engine import build_infrastructure_analysis


LOCAL_BINDS = {"127.0.0.1", "::1", "localhost"}
LOG_DIAGNOSTICS = {
    "journal", "journal_event", "service_log", "service_logs", "kernel_log", "kernel_event",
    "audit_event", "system_event", "event_log", "windows_event_log", "windows_security_event",
    "scm_event", "journal_audit", "system_audit", "boot_service_state", "boot_non_start",
    "config_validate", "filesystem_status", "filesystem_health", "oom_kill", "kernel_status",
}
SERVICE_DIAGNOSTICS = {
    "service_status", "systemd_status", "systemd_service", "service_state",
    "windows_service_status", "scm_service", "scm_service_status",
}
PROCESS_DIAGNOSTICS = {"process_status", "process_snapshot", "process_info", "process_tree", "process_list"}


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
    for value in (
        item.get("observed_at"), item.get("timestamp"), item.get("created_at"),
        raw.get("timestamp"), raw.get("@timestamp"), raw.get("time_created"),
    ):
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
                return str(value)[:500]
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
            if isinstance(value, (int, float)) and value in {0, 1}:
                return bool(value)
            if isinstance(value, str):
                normalized = value.strip().lower()
                if normalized in {"true", "yes", "1", "running", "active", "listening", "reachable", "up", "resolved", "success"}:
                    return True
                if normalized in {"false", "no", "0", "stopped", "inactive", "dead", "unreachable", "down", "failed"}:
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
        values = " ".join(str(raw.get(key) or item.get(key) or "") for key in ("os", "platform", "os_family", "service_manager", "source", "provider"))
        lowered = values.lower()
        diagnostic = _diagnostic(item)
        if any(token in lowered for token in ("linux", "ubuntu", "debian", "rhel", "centos", "rocky", "systemd")) or diagnostic.startswith("systemd"):
            linux += 1
            ids.append(_eid(item, index))
        if any(token in lowered for token in ("windows", "win32", "win64", "service control manager", "scm", "powershell")) or diagnostic.startswith(("windows_", "scm_")):
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
    relevant = diagnostic in PROCESS_DIAGNOSTICS
    pid = process.get("pid") or raw.get("pid") or item.get("pid")
    name = process.get("name") or raw.get("process_name") or raw.get("name")
    if not relevant and pid in (None, "") and name in (None, ""):
        return None
    ppid = process.get("ppid") or parent.get("pid") or raw.get("ppid") or raw.get("parent_pid")
    restart_count = _numeric(item, "restart_count", "restarts", "restart_total")
    stamp = _timestamp(item)
    return {
        "evidence_id": _eid(item, index),
        "timestamp": stamp.isoformat() if stamp else None,
        "name": str(name)[:180] if name not in (None, "") else _scalar(item, "process"),
        "pid": str(pid) if pid not in (None, "") else None,
        "parent_pid": str(ppid) if ppid not in (None, "") else None,
        "parent_name": str(parent.get("name") or raw.get("parent_name") or raw.get("parent_process") or "")[:180] or None,
        "running": _bool(item, "running", "alive", "is_running"),
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
    fields_present = any(key in raw for key in (
        "load_state", "active_state", "sub_state", "result", "main_pid", "exit_status", "restart_count",
        "n_restarts", "failed_dependencies", "win32_exit_code", "service_specific_exit_code", "start_type",
    ))
    if diagnostic not in SERVICE_DIAGNOSTICS and not fields_present:
        return None
    restart_count = _numeric(item, "restart_count", "n_restarts", "restarts")
    exit_status = _numeric(item, "exit_status", "exec_main_status", "status_code", "win32_exit_code")
    manager_raw = (_scalar(item, "service_manager", "manager") or ("scm" if diagnostic.startswith(("windows_", "scm_")) else "systemd")).lower()
    manager = "scm" if manager_raw == "scm" or "service control manager" in manager_raw else manager_raw
    active = (_scalar(item, "active_state", "state", "status") or "unknown").lower()
    if manager == "scm":
        active = {"running": "active", "stopped": "inactive", "stop_pending": "deactivating", "start_pending": "activating"}.get(active, active)
    stamp = _timestamp(item)
    return {
        "evidence_id": _eid(item, index),
        "timestamp": stamp.isoformat() if stamp else None,
        "manager": manager,
        "service": _scalar(item, "service", "unit", "service_name", "name"),
        "load_state": (_scalar(item, "load_state") or ("loaded" if manager == "scm" else "unknown")).lower(),
        "active_state": active,
        "sub_state": (_scalar(item, "sub_state") or "unknown").lower(),
        "result": (_scalar(item, "result", "service_result") or "unknown").lower(),
        "main_pid": _scalar(item, "main_pid", "pid", "exec_main_pid", "process_id"),
        "exit_status": int(exit_status) if exit_status is not None else None,
        "restart_count": int(restart_count) if restart_count is not None and restart_count >= 0 else None,
        "start_timestamp": _scalar(item, "start_timestamp", "active_enter_timestamp", "started_at", "start_time"),
        "failed_dependencies": _failed_dependencies(raw),
        "start_type": _scalar(item, "start_type", "startup_type"),
        "win32_exit_code": _numeric(item, "win32_exit_code"),
        "service_specific_exit_code": _numeric(item, "service_specific_exit_code"),
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
    dependency_failures = [row for row in rows if row.get("failed_dependencies") or row.get("result") == "dependency"]
    restart_loop = [row for row in rows if isinstance(row.get("restart_count"), int) and row["restart_count"] >= 3]
    return {
        "service_states": rows[:40],
        "failed_states": failed[:20],
        "inactive_states": inactive[:20],
        "failed_dependency_states": dependency_failures[:20],
        "restart_loop_candidates": restart_loop[:20],
        "manual_stop_policy": "inactive/dead or exit_status=0 does not prove a manual stop; explicit journal/audit/system actor+action evidence is required",
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


def _message(item: Mapping[str, Any]) -> str:
    raw = _raw(item)
    value = raw.get("message") or raw.get("log") or raw.get("event_message") or item.get("message") or item.get("summary") or ""
    return str(value)[:2000]


def _log_analysis(items: Sequence[Mapping[str, Any]], service_name: Optional[str]) -> Dict[str, Any]:
    entries: List[Dict[str, Any]] = []
    categories: Dict[str, List[Dict[str, Any]]] = {
        "oom_events": [], "kernel_errors": [], "read_only_filesystem": [], "config_errors": [],
        "port_conflicts": [], "crash_events": [], "dependency_events": [], "boot_non_start_events": [],
        "explicit_human_actions": [],
    }
    for index, item in enumerate(items):
        raw = _raw(item)
        diagnostic = _diagnostic(item)
        item_type = str(item.get("type") or "").lower()
        message = _message(item)
        if diagnostic not in LOG_DIAGNOSTICS and item_type not in {"log", "event", "audit"} and not message:
            continue
        stamp = _timestamp(item)
        lower = message.lower()
        row = {
            "evidence_id": _eid(item, index),
            "timestamp": stamp.isoformat() if stamp else None,
            "diagnostic": diagnostic or item_type or "log",
            "source": _scalar(item, "source", "provider", "channel"),
            "service": _scalar(item, "service", "unit", "service_name"),
            "message": message,
            "event_id": _scalar(item, "event_id", "id_code"),
            "provider": _scalar(item, "provider", "event_provider"),
            "channel": _scalar(item, "channel", "log_name"),
        }
        entries.append(row)
        if any(token in lower for token in ("oom-killer", "out of memory", "killed process", "oom kill")) or diagnostic == "oom_kill":
            categories["oom_events"].append(row)
        if any(token in lower for token in ("kernel panic", "i/o error", "ext4-fs error", "xfs error", "kernel bug", "machine check")):
            categories["kernel_errors"].append(row)
        if any(token in lower for token in ("read-only file system", "filesystem read-only", "remounting filesystem read-only")) or _bool(item, "filesystem_read_only") is True:
            categories["read_only_filesystem"].append(row)
        if any(token in lower for token in ("config error", "configuration error", "syntax error", "invalid configuration")) or (diagnostic == "config_validate" and _bool(item, "valid") is False):
            categories["config_errors"].append(row)
        if any(token in lower for token in ("address already in use", "eaddrinuse", "failed to bind", "bind failed")):
            categories["port_conflicts"].append(row)
        if any(token in lower for token in ("segfault", "core dumped", "core dump", "terminated by signal", "service crashed", "fatal signal")):
            categories["crash_events"].append(row)
        if "dependency failed" in lower or "failed dependency" in lower:
            categories["dependency_events"].append(row)
        if any(token in lower for token in ("not started at boot", "failed to start at boot", "boot-time start failed")) or (diagnostic in {"boot_service_state", "boot_non_start"} and _bool(item, "started_at_boot", "started_since_boot") is False):
            categories["boot_non_start_events"].append(row)

        actor = _scalar(item, "actor", "user", "username", "principal", "subject")
        action = _scalar(item, "action", "operation", "verb")
        target = _scalar(item, "target", "service", "unit", "service_name")
        if actor and action and re.search(r"\b(stop|stopped|disable|terminate|kill)\b", action.lower()):
            if not service_name or not target or str(target) == str(service_name):
                action_row = dict(row)
                action_row.update({"actor": actor, "action": action, "target": target})
                categories["explicit_human_actions"].append(action_row)
    entries.sort(key=lambda row: row.get("timestamp") or "")
    return {
        "chronology": entries[:120],
        **{key: value[:30] for key, value in categories.items()},
        "human_action_policy": "human action is confirmed only by explicit actor+action fields in journal/audit/system evidence; wording such as inactive/dead/stopped alone is insufficient",
    }


def _network_analysis(items: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    listeners: List[Dict[str, Any]] = []
    local_tcp: List[Dict[str, Any]] = []
    remote_tcp: List[Dict[str, Any]] = []
    dns: List[Dict[str, Any]] = []
    routes: List[Dict[str, Any]] = []
    interfaces: List[Dict[str, Any]] = []
    host_checks: List[Dict[str, Any]] = []

    for index, item in enumerate(items):
        diagnostic = _diagnostic(item)
        eid = _eid(item, index)
        stamp = _timestamp(item)
        base = {"evidence_id": eid, "timestamp": stamp.isoformat() if stamp else None}
        if diagnostic in {"port_listener_status", "listener_status", "socket_listener", "listener_check"}:
            address = _scalar(item, "bind_address", "address", "listen_address", "host")
            port = _numeric(item, "port", "listen_port", "expected_port")
            error = _scalar(item, "error", "reason", "message")
            listeners.append({
                **base, "listening": _bool(item, "listening", "is_listening", "bound"),
                "bind_address": address, "port": int(port) if port is not None else None,
                "expected_port": _numeric(item, "expected_port"), "error": error,
                "local_only": bool(address and address.lower() in LOCAL_BINDS),
                "port_conflict": bool(error and any(token in error.lower() for token in ("address already in use", "eaddrinuse", "bind failed"))),
            })
        elif diagnostic in {"tcp_check", "tcp_reachability", "socket_connect"}:
            target = _scalar(item, "target", "address", "host", "hostname")
            scope = (_scalar(item, "scope", "check_scope", "origin") or "").lower()
            if not scope:
                scope = "local" if target and target.lower() in LOCAL_BINDS else "remote"
            row = {
                **base, "scope": scope, "target": target,
                "port": _numeric(item, "port"), "reachable": _bool(item, "reachable", "success", "connected"),
                "error": _scalar(item, "error", "reason"),
            }
            (local_tcp if scope in {"local", "loopback", "localhost", "guest"} else remote_tcp).append(row)
        elif diagnostic in {"dns_check", "dns_lookup", "resolver_check"}:
            dns.append({**base, "name": _scalar(item, "name", "hostname", "query"), "resolved": _bool(item, "resolved", "success", "reachable"), "address": _scalar(item, "resolved_address", "address"), "error": _scalar(item, "error", "reason")})
        elif diagnostic in {"route_check", "route_status", "routing_table_check"}:
            routes.append({**base, "destination": _scalar(item, "destination", "target", "network"), "reachable": _bool(item, "reachable", "route_present", "success"), "gateway": _scalar(item, "gateway"), "interface": _scalar(item, "interface", "device"), "error": _scalar(item, "error", "reason")})
        elif diagnostic in {"interface_status", "link_status", "network_interface"}:
            interfaces.append({**base, "interface": _scalar(item, "interface", "device", "name"), "up": _bool(item, "up", "running", "carrier"), "address": _scalar(item, "address", "ip"), "error": _scalar(item, "error", "reason")})
        elif diagnostic in {"host_reachability", "vm_reachability", "ping", "icmp_check"}:
            host_checks.append({**base, "reachable": _bool(item, "reachable", "success", "up"), "target": _scalar(item, "target", "host", "hostname"), "error": _scalar(item, "error", "reason")})

    local_only = [row for row in listeners if row.get("listening") is True and row.get("local_only")]
    missing_listener = [row for row in listeners if row.get("listening") is False]
    port_conflicts = [row for row in listeners if row.get("port_conflict")]
    return {
        "listeners": listeners[:40],
        "missing_listeners": missing_listener[:20],
        "local_only_listeners": local_only[:20],
        "port_conflicts": port_conflicts[:20],
        "local_tcp_checks": local_tcp[:30],
        "remote_tcp_checks": remote_tcp[:30],
        "dns_checks": dns[:30],
        "route_checks": routes[:30],
        "interface_checks": interfaces[:30],
        "host_reachability_checks": host_checks[:20],
    }


def _os_analysis(items: Sequence[Mapping[str, Any]], process: Mapping[str, Any], logs: Mapping[str, Any]) -> Dict[str, Any]:
    clock_skew: List[Dict[str, Any]] = []
    ulimit: List[Dict[str, Any]] = []
    for index, item in enumerate(items):
        diagnostic = _diagnostic(item)
        offset = _numeric(item, "clock_skew_seconds", "time_offset_seconds", "ntp_offset_seconds")
        if diagnostic in {"clock_skew", "time_sync", "ntp_status"} or offset is not None:
            clock_skew.append({
                "evidence_id": _eid(item, index),
                "offset_seconds": offset,
                "synced": _bool(item, "synced", "synchronized", "ntp_synced"),
                "source": _scalar(item, "source", "provider"),
            })
        soft = _numeric(item, "fd_soft_limit", "nofile_soft", "soft_limit")
        hard = _numeric(item, "fd_hard_limit", "nofile_hard", "hard_limit")
        used = _numeric(item, "fd_used", "open_fds", "file_descriptors")
        if diagnostic in {"ulimit", "fd_limit", "resource_limit"} or soft is not None or hard is not None:
            pressure = used is not None and soft is not None and soft > 0 and used / soft >= 0.9
            ulimit.append({
                "evidence_id": _eid(item, index), "fd_used": used, "fd_soft_limit": soft,
                "fd_hard_limit": hard, "pressure": pressure,
            })
    return {
        "oom_events": list(logs.get("oom_events") or []),
        "kernel_errors": list(logs.get("kernel_errors") or []),
        "read_only_filesystem": list(logs.get("read_only_filesystem") or []),
        "clock_skew": clock_skew[:20],
        "clock_skew_failures": [row for row in clock_skew if row.get("synced") is False or (row.get("offset_seconds") is not None and abs(float(row["offset_seconds"])) >= 5)][:20],
        "ulimit_fd": ulimit[:20],
        "fd_pressure": list(process.get("fd_pressure_candidates") or [])[:20] + [row for row in ulimit if row.get("pressure")][:20],
    }


def _status(value: Optional[bool], *, no_evidence: bool = False) -> str:
    if no_evidence or value is None:
        return "unknown"
    return "pass" if value else "fail"


def _chain(
    items: Sequence[Mapping[str, Any]],
    service: Mapping[str, Any],
    process: Mapping[str, Any],
    network: Mapping[str, Any],
    os_analysis: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    all_ids = [_eid(item, index) for index, item in enumerate(items)]
    host_checks = list(network.get("host_reachability_checks") or [])
    if host_checks:
        host_ok = any(row.get("reachable") is True for row in host_checks)
        host_status = _status(host_ok)
        host_ids = [row["evidence_id"] for row in host_checks]
    elif items:
        host_status, host_ids = "pass", all_ids[:8]
    else:
        host_status, host_ids = "unknown", []

    os_bad = bool(os_analysis.get("oom_events") or os_analysis.get("kernel_errors") or os_analysis.get("read_only_filesystem") or os_analysis.get("clock_skew_failures") or os_analysis.get("fd_pressure"))
    os_evidence = []
    for key in ("oom_events", "kernel_errors", "read_only_filesystem", "clock_skew_failures", "fd_pressure"):
        for row in os_analysis.get(key) or []:
            if isinstance(row, Mapping) and row.get("evidence_id"):
                os_evidence.append(str(row["evidence_id"]))
    os_status = "fail" if os_bad else ("pass" if os_evidence or items else "unknown")

    service_rows = list(service.get("service_states") or [])
    service_active_values = [row.get("active_state") == "active" for row in service_rows if row.get("active_state") not in {None, "unknown"}]
    service_status = _status(any(service_active_values), no_evidence=not service_active_values)
    process_rows = list(process.get("processes") or [])
    running_values = [row.get("running") for row in process_rows if row.get("running") is not None]
    process_status = _status(any(value is True for value in running_values), no_evidence=not running_values)

    listeners = list(network.get("listeners") or [])
    listener_values = [row.get("listening") for row in listeners if row.get("listening") is not None]
    listener_status = _status(any(value is True for value in listener_values), no_evidence=not listener_values)
    local_rows = list(network.get("local_tcp_checks") or [])
    local_values = [row.get("reachable") for row in local_rows if row.get("reachable") is not None]
    local_status = _status(any(value is True for value in local_values), no_evidence=not local_values)
    remote_rows = list(network.get("remote_tcp_checks") or [])
    remote_values = [row.get("reachable") for row in remote_rows if row.get("reachable") is not None]
    remote_status = _status(any(value is True for value in remote_values), no_evidence=not remote_values)

    path_rows = list(network.get("dns_checks") or []) + list(network.get("route_checks") or []) + list(network.get("interface_checks") or [])
    path_values: List[bool] = []
    for row in path_rows:
        value = row.get("resolved") if "resolved" in row else row.get("reachable") if "reachable" in row else row.get("up")
        if value is not None:
            path_values.append(bool(value))
    path_status = "unknown" if not path_values else ("pass" if all(path_values) else "fail")

    return [
        {"stage": "host_reachable", "status": host_status, "evidence_ids": list(dict.fromkeys(host_ids))[:12]},
        {"stage": "os_healthy", "status": os_status, "evidence_ids": list(dict.fromkeys(os_evidence))[:12]},
        {"stage": "service_active", "status": service_status, "evidence_ids": [row["evidence_id"] for row in service_rows[:12]]},
        {"stage": "process_alive", "status": process_status, "evidence_ids": [row["evidence_id"] for row in process_rows[:12]]},
        {"stage": "port_listening", "status": listener_status, "evidence_ids": [row["evidence_id"] for row in listeners[:12]]},
        {"stage": "local_tcp", "status": local_status, "evidence_ids": [row["evidence_id"] for row in local_rows[:12]]},
        {"stage": "remote_tcp", "status": remote_status, "evidence_ids": [row["evidence_id"] for row in remote_rows[:12]]},
        {"stage": "dns_route_interface", "status": path_status, "evidence_ids": [row["evidence_id"] for row in path_rows[:12]]},
    ]


def _fault_classification(
    service: Mapping[str, Any],
    process: Mapping[str, Any],
    logs: Mapping[str, Any],
    network: Mapping[str, Any],
    os_analysis: Mapping[str, Any],
    boot: Mapping[str, Any],
) -> Dict[str, Any]:
    observations: List[Dict[str, Any]] = []
    causes: List[Dict[str, Any]] = []
    human_actions: List[Dict[str, Any]] = list(logs.get("explicit_human_actions") or [])

    def add(target: List[Dict[str, Any]], code: str, rows: Sequence[Mapping[str, Any]], handoff: Optional[str] = None) -> None:
        ids = [str(row.get("evidence_id")) for row in rows if row.get("evidence_id")]
        entry: Dict[str, Any] = {"code": code, "evidence_ids": list(dict.fromkeys(ids))[:20]}
        if handoff:
            entry["handoff"] = handoff
        if entry not in target:
            target.append(entry)

    if service.get("inactive_states"):
        add(observations, "service_inactive_observed", service["inactive_states"])
    if process.get("absent_processes"):
        add(observations, "process_missing_observed", process["absent_processes"])
    if network.get("missing_listeners"):
        add(observations, "listener_missing_observed", network["missing_listeners"])
    if network.get("local_only_listeners"):
        add(causes, "listener_local_only", network["local_only_listeners"], "network")
    if service.get("restart_loop_candidates"):
        add(causes, "restart_loop", service["restart_loop_candidates"])
    if service.get("failed_dependency_states") or logs.get("dependency_events"):
        add(causes, "dependency_failure", list(service.get("failed_dependency_states") or []) + list(logs.get("dependency_events") or []), "dependency")
    crash_service_rows = [row for row in service.get("failed_states") or [] if row.get("result") in {"exit-code", "signal", "core-dump", "watchdog", "timeout"} or row.get("exit_status") not in {None, 0}]
    if logs.get("crash_events") or crash_service_rows:
        add(causes, "service_crash", list(logs.get("crash_events") or []) + crash_service_rows)
    boot_non_start_rows = list(logs.get("boot_non_start_events") or [])
    if boot.get("boot_time"):
        boot_non_start_rows.extend([row for row in service.get("inactive_states") or [] if str(row.get("start_type") or "").lower() in {"auto", "automatic", "enabled"} and not row.get("start_timestamp")])
    if boot_non_start_rows:
        add(causes, "boot_time_non_start", boot_non_start_rows)
    if logs.get("config_errors"):
        add(causes, "config_error", logs["config_errors"])
    if logs.get("port_conflicts") or network.get("port_conflicts"):
        add(causes, "port_conflict", list(logs.get("port_conflicts") or []) + list(network.get("port_conflicts") or []), "network")
    if os_analysis.get("oom_events"):
        add(causes, "oom_kill", os_analysis["oom_events"], "infrastructure")

    local_ok = any(row.get("reachable") is True for row in network.get("local_tcp_checks") or [])
    remote_fail_rows = [row for row in network.get("remote_tcp_checks") or [] if row.get("reachable") is False]
    path_fail_rows = (
        [row for row in network.get("dns_checks") or [] if row.get("resolved") is False]
        + [row for row in network.get("route_checks") or [] if row.get("reachable") is False]
        + [row for row in network.get("interface_checks") or [] if row.get("up") is False]
    )
    if (local_ok and remote_fail_rows) or path_fail_rows:
        add(causes, "network_path_failure", remote_fail_rows + path_fail_rows, "network")

    running = any(row.get("running") is True for row in process.get("processes") or [])
    if running and network.get("missing_listeners"):
        add(causes, "process_running_no_listener", network["missing_listeners"])
    if human_actions:
        add(causes, "manual_stop_confirmed", human_actions)

    return {
        "observations": observations[:20],
        "causal_candidates": causes[:20],
        "confirmed_human_actions": human_actions[:20],
        "policy": "service stop, crash, dependency failure, boot-time non-start, config error, port conflict and network path failure remain separate classes; manual stop requires explicit actor+action evidence",
    }


def _causal_findings(
    host: Mapping[str, Any],
    process: Mapping[str, Any],
    service: Mapping[str, Any],
    boot: Mapping[str, Any],
    faults: Mapping[str, Any],
    os_analysis: Mapping[str, Any],
) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    matrix = host.get("health_matrix") if isinstance(host.get("health_matrix"), Mapping) else {}
    cpu = matrix.get("cpu") if isinstance(matrix.get("cpu"), Mapping) else {}
    disk = matrix.get("disk") if isinstance(matrix.get("disk"), Mapping) else {}
    memory = matrix.get("memory") if isinstance(matrix.get("memory"), Mapping) else {}

    if cpu.get("status") == "saturated":
        findings.append({"code": "guest_cpu_saturation", "evidence_ids": cpu.get("evidence_ids") or [], "handoff": "infrastructure"})
    elif cpu.get("status") == "virtualization_contention":
        findings.append({"code": "guest_virtualization_contention", "evidence_ids": cpu.get("evidence_ids") or [], "handoff": "infrastructure"})
    if cpu.get("status") == "waiting_on_io" and disk.get("status") in {"io_bottleneck", "device_error"}:
        findings.append({"code": "storage_pressure_visible_as_guest_cpu_wait", "evidence_ids": list(dict.fromkeys((disk.get("evidence_ids") or []) + (cpu.get("evidence_ids") or []))), "handoff": "storage"})
    disk_codes = {
        "io_bottleneck": "guest_disk_io_bottleneck",
        "device_error": "guest_disk_device_error",
        "inode_pressure": "guest_inode_pressure",
        "capacity_pressure": "guest_filesystem_capacity_pressure",
    }
    if str(disk.get("status") or "") in disk_codes:
        findings.append({"code": disk_codes[str(disk["status"])], "evidence_ids": disk.get("evidence_ids") or [], "handoff": "storage"})
    if memory.get("status") in {"oom_pressure", "swap_storm", "pressured"}:
        findings.append({"code": "guest_memory_pressure", "evidence_ids": memory.get("evidence_ids") or [], "handoff": "infrastructure"})
    if process.get("absent_processes"):
        findings.append({"code": "process_not_running_observed", "evidence_ids": [str(row["evidence_id"]) for row in process["absent_processes"] if row.get("evidence_id")]})
    if process.get("restart_behavior_candidates"):
        findings.append({"code": "process_restart_churn", "evidence_ids": [str(row["evidence_id"]) for row in process["restart_behavior_candidates"] if row.get("evidence_id")]})
    if process.get("fd_pressure_candidates"):
        findings.append({"code": "process_fd_pressure", "evidence_ids": [str(row["evidence_id"]) for row in process["fd_pressure_candidates"] if row.get("evidence_id")]})
    if service.get("failed_states"):
        findings.append({"code": "systemd_failed_state", "evidence_ids": [str(row["evidence_id"]) for row in service["failed_states"] if row.get("evidence_id")]})
    elif service.get("inactive_states"):
        findings.append({"code": "systemd_inactive_observed", "evidence_ids": [str(row["evidence_id"]) for row in service["inactive_states"] if row.get("evidence_id")]})
    if service.get("failed_dependency_states"):
        findings.append({"code": "systemd_failed_dependency", "evidence_ids": [str(row["evidence_id"]) for row in service["failed_dependency_states"] if row.get("evidence_id")], "handoff": "dependency"})
    if service.get("restart_loop_candidates"):
        findings.append({"code": "service_restart_loop", "evidence_ids": [str(row["evidence_id"]) for row in service["restart_loop_candidates"] if row.get("evidence_id")]})
    if boot.get("reboot_events"):
        near = [row for row in boot["reboot_events"] if row.get("incident_offset_seconds") is not None and abs(float(row["incident_offset_seconds"])) <= 900]
        if near:
            findings.append({"code": "reboot_near_incident", "evidence_ids": [str(row["evidence_id"]) for row in near]})
    if os_analysis.get("read_only_filesystem"):
        findings.append({"code": "filesystem_read_only", "evidence_ids": [str(row["evidence_id"]) for row in os_analysis["read_only_filesystem"] if row.get("evidence_id")], "handoff": "storage"})
    if os_analysis.get("clock_skew_failures"):
        findings.append({"code": "clock_time_skew", "evidence_ids": [str(row["evidence_id"]) for row in os_analysis["clock_skew_failures"] if row.get("evidence_id")]})
    for row in list(faults.get("causal_candidates") or []) + list(faults.get("observations") or []):
        if isinstance(row, Mapping) and row.get("code") and not any(existing.get("code") == row.get("code") and existing.get("evidence_ids") == row.get("evidence_ids") for existing in findings):
            findings.append(dict(row))
    return findings[:32]


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
    logs = _log_analysis(items, service_name)
    network = _network_analysis(items)
    os_analysis = _os_analysis(items, process, logs)
    chain = _chain(items, service, process, network, os_analysis)
    faults = _fault_classification(service, process, logs, network, os_analysis, boot)
    causal = _causal_findings(host, process, service, boot, faults, os_analysis)

    handoffs: List[str] = []
    for target in list(host.get("handoff_candidates") or []) + [row.get("handoff") for row in causal]:
        target = str(target or "")
        if target and target != "vm" and target not in handoffs:
            handoffs.append(target)

    gaps: List[Dict[str, Any]] = []
    if not host.get("metric_kinds"):
        gaps.append({"evidence": "guest host metrics: CPU/load/iowait/steal, memory/swap/PSI, disk/inode/I/O/filesystem", "information_gain": 0.97})
    if process.get("process_count") == 0:
        gaps.append({"evidence": "process snapshot with PID/PPID CPU memory FD sockets and restart state", "information_gain": 0.94})
    if not service.get("service_states"):
        gaps.append({"evidence": "systemd service state: load/active/sub/result/main PID/exit/restarts/start/failed dependencies or Windows SCM equivalent", "information_gain": 0.96})
    if not boot.get("boot_time") and not boot.get("reboot_events"):
        gaps.append({"evidence": "boot time and reboot history", "information_gain": 0.78})
    if not logs.get("chronology"):
        gaps.append({"evidence": "journal/service/kernel logs or Windows Event Log with timestamps; audit actor/action when human action is suspected", "information_gain": 0.95})
    if not network.get("listeners"):
        gaps.append({"evidence": "expected listener/port and bind address", "information_gain": 0.94})
    if not network.get("local_tcp_checks"):
        gaps.append({"evidence": "local TCP reachability from the guest", "information_gain": 0.92})
    if not network.get("remote_tcp_checks"):
        gaps.append({"evidence": "remote TCP reachability from a client-side vantage point", "information_gain": 0.9})
    if not network.get("dns_checks") and not network.get("route_checks") and not network.get("interface_checks"):
        gaps.append({"evidence": "DNS resolution, route and interface/link status", "information_gain": 0.86})
    gaps.sort(key=lambda row: float(row["information_gain"]), reverse=True)

    platform = _platform(items)
    return {
        "policy": "guest diagnosis is evidence-driven; host utilization alone is not saturation; inactive/dead or exit status 0 never proves manual stop",
        "service": service_name,
        "platform_detection": platform,
        "incident_start": incident_start.isoformat() if incident_start else None,
        "host_analysis": host,
        "process_analysis": process,
        "service_analysis": {
            **service,
            "log_analysis": logs,
            "network_analysis": network,
            "os_analysis": os_analysis,
            "diagnostic_chain": chain,
            "fault_classification": faults,
            "windows_extension": {
                "service_manager": "Service Control Manager",
                "event_log": "Windows Event Log",
                "supported_diagnostics": ["windows_service_status", "scm_service", "windows_event_log", "windows_security_event", "process_status", "port_listener_status", "tcp_check", "dns_lookup", "route_check", "interface_status"],
                "connector_limited": platform.get("platform") != "windows" or not any(row.get("manager") == "scm" for row in service.get("service_states") or []),
            },
        },
        "boot_reboot_analysis": boot,
        "log_analysis": logs,
        "network_analysis": network,
        "os_analysis": os_analysis,
        "diagnostic_chain": chain,
        "fault_classification": faults,
        "causal_findings": causal,
        "handoff_candidates": handoffs[:8],
        "evidence_gaps": gaps[:10],
        "next_best_evidence": gaps[:8],
        "analysis_stages": ["platform", "host_use", "os", "service_manager", "process", "logs_chronology", "listener", "local_tcp", "remote_tcp", "dns_route_interface", "boot_reboot", "causal_synthesis"],
    }
