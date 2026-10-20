"""Universal read-only downstream dependency investigation on trusted VM MCP edge.

Requires service identity and systemd-verified config-file path. Models never
provide targets. No config values, credentials, raw logs or HTTP bodies escape.
"""
from __future__ import annotations
import base64
import hashlib
import re
import shlex
from typing import Any

from integrations.vm.dependency_discovery import discover, load_config
from integrations.vm.dependency_llm_binding import resolve_llm_bindings, safe_candidate_fields
from integrations.vm.general_config_review import checked_config_path, remote_config_read_command
from integrations.vm.protocol_diagnostics import redis_unauthenticated_ping

MAX_FILES = 4
MAX_CHECKS = 6
MAX_ENCODED = 349528
SUPPORTED = (".json", ".yaml", ".yml", ".toml", ".properties", ".ini", ".cfg", ".cnf", ".conf", ".xml", ".config")


async def http_head(connector: Any, target: str, *, host: str, port: int, scheme: str) -> dict:
    """HEAD '/' only, no auth, redirects, proxy, body or user-provided URL path."""
    connector._validate_remote_host(host)
    port = connector._validate_port(port)
    if scheme not in {"http", "https"}:
        return {"supported": False, "http_status": None, "tls_verified": None}
    # Host comes from verified config and was validated again before quoting.
    uri_host = "[" + host + "]" if ":" in host else host
    uri = scheme + "://" + uri_host + ":" + str(port) + "/"
    cmd = (
        "if ! command -v curl >/dev/null 2>&1; then printf 'unsupported'; "
        "else curl --head --silent --show-error --max-time 5 --connect-timeout 3 "
        "--max-redirs 0 --noproxy '*' --output /dev/null "
        "--write-out '%{http_code} %{ssl_verify_result}' -- "
        + shlex.quote(uri) + " 2>/dev/null; fi"
    )
    try:
        result = await connector._run(target, cmd)
        output = str(result.get("stdout") or "").strip()
        if output == "unsupported":
            return {"supported": False, "http_status": None, "tls_verified": None}
        fields = output.split()
        code = int(fields[0]) if fields and fields[0].isdigit() else None
        tls_code = int(fields[1]) if len(fields) > 1 and fields[1].isdigit() else None
        if not result.get("success") or code is None or code < 100 or code > 599:
            return {"supported": True, "http_status": None, "tls_verified": None}
        return {"supported": True, "http_status": code,
                "tls_verified": (tls_code == 0 if scheme == "https" else None)}
    except Exception:
        return {"supported": False, "http_status": None, "tls_verified": None}


_DB_KINDS = {
    "database_tcp", "postgres", "postgresql", "mysql", "mariadb",
    "mssql", "sqlserver", "oracle", "mongodb", "cassandra", "db2", "neo4j",
}
_MQ_KINDS = {"activemq", "rabbitmq", "kafka", "amqp", "nats", "mqtt", "zookeeper"}


def _matches_priority(kind: str, family: str) -> bool:
    return (
        kind in _DB_KINDS if family == "database" else
        kind in _MQ_KINDS if family in {"messaging", "message_broker"} else
        kind in {"redis", "valkey", "keydb"} if family in {"redis", "cache"} else
        kind in {"http", "https", "grpc"} if family in {"http", "http_dependency"} else
        False
    )


async def investigate(
    connector: Any, target: str, service: str, *,
    mode: str = "probe", selections: list[dict] | None = None,
    priority_family: str = "", include_full_config: bool = False,
) -> dict:
    connector._validate_target(target)
    connector._validate_service(service)
    if mode not in {"probe", "discover"}:
        raise ValueError("vm_dependency_mode_invalid")
    if type(include_full_config) is not bool or (include_full_config and mode != "discover"):
        raise ValueError("vm_dependency_full_context_mode_invalid")
    if include_full_config:
        from domain.contracts.config import settings
        if not settings.AIOPS_DEPENDENCY_LLM_FULL_CONFIG_ENABLED:
            raise PermissionError("vm_dependency_full_context_not_enabled")
    if priority_family not in {"", "database", "messaging", "message_broker",
                               "redis", "cache", "http", "http_dependency"}:
        raise ValueError("vm_dependency_priority_invalid")
    if selections is not None and (mode != "probe" or not isinstance(selections, list)
                                   or len(selections) > MAX_FILES):
        raise ValueError("vm_dependency_selections_invalid")
    choices: dict[int, dict] = {}
    for item in selections or []:
        if not isinstance(item, dict) or set(item) != {
            "file_index", "sha256", "pairs", "endpoint_ids"
        }:
            raise ValueError("vm_dependency_selection_shape_invalid")
        idx, digest = item["file_index"], item["sha256"]
        if (type(idx) is not int or not 0 <= idx < MAX_FILES or idx in choices
                or not isinstance(digest, str)
                or re.fullmatch(r"[a-f0-9]{64}", digest) is None
                or not isinstance(item["pairs"], list)
                or not isinstance(item["endpoint_ids"], list)
                or len(item["pairs"]) > 6 or len(item["endpoint_ids"]) > 6):
            raise ValueError("vm_dependency_selection_fields_invalid")
        choices[idx] = item
    baseline = {
        "success": False, "target": target, "service": service,
        "status": "not_verified", "diagnostic": "dependency_investigation",
        "read_only": True, "execution_authority": False, "root_cause_confirmed": False,
        "application_health_verified": False, "protocol_health_verified": False,
        "config_contents_exposed": False, "secrets_exposed": False,
        "config_files_read": 0, "config_files_checked": 0,
        "config_files_parse_failed": 0, "checks_executed": 0, "dependencies": [],
        "limitations": ["network_probe_not_equal_protocol_health"],
        "investigation_status": "not_started", "next_checks": [],
        "llm_field_binding_status": "not_requested",
        "llm_field_binding_files": [],
    }
    try:
        discovered = await connector.service_config_discovery(target, service)
    except Exception:
        return {**baseline, "status": "config_discovery_unavailable"}
    if discovered.get("success") is not True:
        return {**baseline, "status": "config_discovery_unavailable"}
    base = {**baseline, "success": True}
    # No guessed file based solely on an LLM name or generic filesystem scan.
    filenames = [
        row["path"] for row in (discovered.get("files") or [])[:24]
        if isinstance(row, dict) and row.get("verified_exists") is True
        and isinstance(row.get("path"), str)
        and row["path"].lower().endswith(SUPPORTED)
    ]
    if not filenames:
        return {**base, "status": "no_verified_config_files",
                "limitations": ["systemd_config_path_not_verified"]}
    # Prefer application settings over unrelated JSON resources when the
    # verified runtime lists more files than the bounded read budget.
    # Presence alone still does not establish the effective environment.
    def _config_priority(path: str) -> tuple[int, str]:
        filename = path.rsplit("/", 1)[-1].lower()
        if filename == "appsettings.production.json":
            return 0, filename
        if filename in {"appsettings.json", "application-production.yml",
                        "application-production.yaml", "application-production.properties"}:
            return 1, filename
        if filename.startswith("appsettings.") and filename.endswith(".json"):
            return 2, filename
        if filename in {"application.yml", "application.yaml",
                        "application.properties", "application.toml"}:
            return 2, filename
        if any(marker in filename for marker in ("database", "connection", "config", "settings")):
            return 3, filename
        return 5, filename

    filenames = sorted(dict.fromkeys(filenames), key=_config_priority)
    by_file: list[list[dict]] = []
    read_failed = 0
    if mode == "discover":
        base["binding_candidates"] = []
    for file_index, path in enumerate(list(dict.fromkeys(filenames))[:MAX_FILES]):
        try:
            verified_path = checked_config_path(path)
            cmd = remote_config_read_command(verified_path)
            response = await connector._run(target, cmd)
            if response.get("success") is not True:
                read_failed += 1
                continue
            encoded = str(response.get("stdout") or "").strip()
            if not (4 <= len(encoded) <= MAX_ENCODED):
                read_failed += 1
                continue
            raw = base64.b64decode(encoded, validate=True)
            if not (1 <= len(raw) <= 262144):
                read_failed += 1
                continue
            base["config_files_read"] += 1
            try:
                config = load_config(raw.decode("utf-8-sig"), path)
            except (UnicodeError, ValueError, TypeError):
                # Syntax/encoding is invalid or unsupported; never echo
                # parser exceptions (they can include secret config bytes).
                base["config_files_parse_failed"] += 1
                continue
            base["config_files_checked"] += 1
            fingerprint = hashlib.sha256(raw).hexdigest()
            if mode == "discover":
                facts = safe_candidate_fields(config)
                # Worker returns only whitelisted structural Host/Port IDs.
                # Never raw config, DSN text, passwords or arbitrary values.
                # Optional, transient context to the authenticated central AIOps
                # process only. Never truncate a secret-bearing document.
                # Public incident evidence and probe results must not retain it.
                full_context = (
                    {"complete_config_b64": encoded}
                    if include_full_config and len(raw) <= 65536 else {}
                )
                base["binding_candidates"].append({
                    "file_index": file_index,
                    "config_file": verified_path,
                    "sha256": fingerprint,
                    **facts, **full_context,
                })
                if full_context:
                    base["config_contents_exposed"] = True
                    base["secrets_exposed"] = True
                base["llm_field_binding_files"].append({
                    "config_file": verified_path,
                    "status": "central_llm_required" if (
                        (facts["host_fields"] and facts["port_fields"])
                        or facts["inline_endpoint_fields"]
                    ) else "no_safe_host_port_candidates",
                    "candidate_host_count": len(facts["host_fields"]),
                    "candidate_port_count": len(facts["port_fields"]),
                    "candidate_inline_endpoint_count": len(facts["inline_endpoint_fields"]),
                    "verified_pair_count": 0,
                })
                continue
            provided = choices.get(file_index)
            if provided is not None and provided["sha256"] != fingerprint:
                # Config changed between central selection and the worker's
                # independent reread. Do not probe a stale LLM binding.
                base["llm_field_binding_files"].append({
                    "config_file": verified_path, "status": "config_changed",
                    "candidate_host_count": 0, "candidate_port_count": 0,
                    "candidate_inline_endpoint_count": 0, "verified_pair_count": 0,
                })
                base["llm_field_binding_status"] = "config_changed"
                continue
            # Preserve the exact verified source file and structural setting
            # key; only selected endpoint facts leave the trusted worker.
            # The entire verified document is parsed on the trusted worker.
            # LLM receives only host/port field IDs, paths and safe literal
            # values; never source bytes, secrets, or arbitrary config strings.
            llm = (await resolve_llm_bindings(
                config, selection={
                    "pairs": provided["pairs"],
                    "endpoint_ids": provided["endpoint_ids"],
                },
            ) if provided is not None else await resolve_llm_bindings(config))
            base["llm_field_binding_files"].append({
                "config_file": verified_path,
                "status": llm["status"],
                "candidate_host_count": llm["candidate_host_count"],
                "candidate_port_count": llm["candidate_port_count"],
                "candidate_inline_endpoint_count": llm["candidate_inline_endpoint_count"],
                "verified_pair_count": len(llm["endpoints"]),
            })
            selected = llm["endpoints"]
            # Aggregate across files without letting later *empty* config
            # files hide a meaningful failure on the application config.
            # In particular, no_safe_host_port_candidates must not overwrite
            # trusted_llm_not_configured from a file with 6 Host/Port fields.
            binding_rank = {
                "not_requested": 0,
                "no_safe_host_port_candidates": 1,
                "no_model_match": 2,
                "trusted_llm_not_configured": 3,
                "llm_binding_unavailable": 4,
                "llm_response_incomplete": 5,
                "llm_response_invalid": 6,
                "llm_unsubstantiated_selection": 7,
                "llm_cross_dependency_selection": 7,
                "central_llm_required": 3,
                "central_llm_unavailable": 4,
                "config_changed": 9,
                "verified": 8,
            }
            current = str(base["llm_field_binding_status"])
            candidate = "verified" if selected else str(llm["status"])
            if binding_rank.get(candidate, 0) > binding_rank.get(current, 0):
                base["llm_field_binding_status"] = candidate
            static = discover(config)
            selected_targets = {(item["kind"], item["host"]) for item in selected}
            # A vendor-default inference must not compete with a precisely
            # bound value discovered in the same configuration.
            static = [
                row for row in static
                if not (row.get("port_inferred") is True and
                        (row["kind"], row["host"]) in selected_targets)
            ]
            # Preserve one confirmed destination per technology before
            # filling the per-file budget with additional peers. Without
            # diversity, six Redis endpoints can consume the entire budget
            # and hide a configured SQL database or Kafka broker in the same
            # service config. Every candidate remains independently parsed.
            candidates = selected + static
            kinds: set[str] = set()
            representatives: list[dict] = []
            peers: list[dict] = []
            for item in candidates:
                kind = item["kind"]
                if kind not in kinds:
                    representatives.append(item)
                    kinds.add(kind)
                else:
                    peers.append(item)
            ordered = representatives + peers
            if priority_family:
                ordered.sort(key=lambda item: not _matches_priority(
                    str(item.get("kind") or ""), priority_family))
            by_file.append([
                {**item, "config_file": verified_path}
                for item in ordered[:MAX_CHECKS]
            ])
        except Exception:
            # No parser trace or input excerpts: they can contain credentials.
            read_failed += 1
    base["config_files_failed"] = read_failed
    if mode == "discover":
        base["status"] = "binding_candidates_ready"
        base["llm_field_binding_status"] = (
            "central_llm_required" if any(
                f["status"] == "central_llm_required"
                for f in base["llm_field_binding_files"]
            ) else "no_safe_host_port_candidates"
        )
        base["investigation_status"] = "awaiting_central_llm"
        return base
    if priority_family:
        # Exact alert focus: NEVER spend a database incident's probe budget
        # on Redis/HTTP or report those checks as database verification.
        # The model cannot elevate an unrelated dependency to this scope.
        by_file = [
            [row for row in group
             if _matches_priority(str(row.get("kind") or ""), priority_family)]
            for group in by_file
        ]
    # Never persist the complete parsed config or prompt in incident evidence.
    # Only bounded field counts, path provenance, and transport outcomes leave.
    # Spread the fixed probe budget across verified files. Otherwise one
    # config with six endpoints can starve the failing dependency in another.
    known: list[dict] = []
    seen: set[tuple[str, str, int]] = set()
    for index in range(MAX_CHECKS):
        for group in by_file:
            if index >= len(group):
                continue
            item = group[index]
            identity = (item["kind"], item["host"], item["port"])
            if identity not in seen:
                seen.add(identity)
                known.append(item)
            if len(known) >= MAX_CHECKS:
                break
        if len(known) >= MAX_CHECKS:
            break
    if not known:
        base["status"] = (
            "alert_dependency_not_discovered" if priority_family and
            base["config_files_checked"] else
            "dependency_not_discovered" if base["config_files_checked"]
            else "config_parse_failed" if base["config_files_parse_failed"]
            else "config_read_unavailable"
        )
        base["limitations"] = [
            "no_config_verified_endpoint_for_alert_family" if priority_family
            else "no_static_dependency_endpoint_verified"
        ]
        return base
    followups: list[str] = []
    saw_unreachable = False
    saw_protocol_response = False
    for dependency in known:
        record = dict(dependency)
        try:
            if record.get("port_inferred") is True:
                # A TCP handshake with a vendor's default port says nothing
                # about an application's effective configured destination.
                # Never probe a guessed port or classify it as healthy.
                record["probe_scope"] = "not_executed_inferred_port"
                record["probe_supported"] = False
                record["tcp_reachable"] = None
                record["probe_status"] = "port_unverified"
                record["protocol_status"] = "not_executed"
                record["protocol_health_verified"] = False
                if "verify_effective_dependency_port" not in followups:
                    followups.append("verify_effective_dependency_port")
                base["dependencies"].append(record)
                continue
            if record["probe"] == "http_head":
                # Only the configured origin is probed. We do not send tokens,
                # URI paths or parameters to the destination or the LLM.
                record["probe_scope"] = "origin_root_head"
                http = await http_head(
                    connector, target, host=record["host"],
                    port=record["port"], scheme=record["kind"],
                )
                record["probe_supported"] = http["supported"]
                record["http_status"] = http["http_status"]
                record["tls_verified"] = http["tls_verified"]
                record["probe_status"] = (
                    "http_responded" if http["http_status"] is not None else
                    "unsupported" if not http["supported"] else "unavailable"
                )
            else:
                record["probe_scope"] = "transport_tcp_connect"
                tcp = await connector.tcp_check(target, record["host"], record["port"])
                record["probe_supported"] = (tcp.get("success") is True
                                             and tcp.get("supported") is True)
                reached = tcp.get("reachable") if record["probe_supported"] else None
                record["tcp_reachable"] = reached if type(reached) is bool else None
                record["probe_status"] = (
                    "tcp_reachable" if record["tcp_reachable"] is True else
                    "tcp_unreachable" if record["tcp_reachable"] is False else
                    "unverified"
                )
                if record["tcp_reachable"] is False:
                    saw_unreachable = True
                    # The consumer VM is the right vantage point. Only a
                    # config-verified endpoint, never an LLM-selected host,
                    # is passed to bounded DNS and routing tools.
                    try:
                        dns = await connector.dns_check(target, record["host"])
                        record["dns_resolved"] = (
                            dns.get("resolved") if dns.get("success") is True
                            and type(dns.get("resolved")) is bool else None
                        )
                    except Exception:
                        record["dns_resolved"] = None
                    if record["dns_resolved"] is False:
                        if "review_dns_configuration" not in followups:
                            followups.append("review_dns_configuration")
                    else:
                        try:
                            route = await connector.route_check(target, record["host"])
                            record["route_found"] = (
                                route.get("route_found") if route.get("success") is True
                                and type(route.get("route_found")) is bool else None
                            )
                        except Exception:
                            record["route_found"] = None
                        if "review_network_path" not in followups:
                            followups.append("review_network_path")
                elif record["tcp_reachable"] is True and record["kind"] == "redis":
                    try:
                        protocol = await redis_unauthenticated_ping(
                            connector, target, record["host"], record["port"],
                            tls=record.get("tls_requested") is True,
                        )
                    except Exception:
                        protocol = {
                            "protocol_status": "probe_unavailable",
                            "protocol_supported": False,
                            "protocol_health_verified": False,
                        }
                    record.update(protocol)
                    if protocol["protocol_status"] in {
                        "authentication_required", "access_denied",
                    }:
                        saw_protocol_response = True
                        if "compare_application_auth_settings" not in followups:
                            followups.append("compare_application_auth_settings")
                    elif protocol["protocol_status"] == "unauthenticated_ping_ok":
                        saw_protocol_response = True
                        if "inspect_client_timeouts_pool_and_errors" not in followups:
                            followups.append("inspect_client_timeouts_pool_and_errors")
                    elif protocol["protocol_status"] == "tls_handshake_unverified":
                        if "review_tls_mode_and_certificates" not in followups:
                            followups.append("review_tls_mode_and_certificates")
                    else:
                        if "protocol_check_unavailable" not in followups:
                            followups.append("protocol_check_unavailable")
                elif record["tcp_reachable"] is True:
                    if "protocol_check_unavailable" not in followups:
                        followups.append("protocol_check_unavailable")
        except Exception:
            record["probe_supported"] = False
            record["probe_status"] = "check_unavailable"
        base["checks_executed"] += 1
        base["dependencies"].append(record)
    # A decoded configuration with only inferred ports is not a completed
    # connectivity test. Explicitly distinguish discovery from probe evidence.
    base["status"] = (
        "port_unverified" if not base["checks_executed"] and
        any(row.get("probe_status") == "port_unverified"
            for row in base["dependencies"])
        else "checks_completed"
    )
    base["next_checks"] = followups[:6]
    base["investigation_status"] = (
        "transport_failure_observed" if saw_unreachable else
        "redis_protocol_responded" if saw_protocol_response else
        "port_unverified" if any(
            row.get("probe_status") == "port_unverified" for row in base["dependencies"]
        ) else "dependency_endpoint_checked"
    )
    base["protocol_health_verified"] = any(
        row.get("protocol_health_verified") is True
        for row in base["dependencies"]
    )
    # Even a PONG is not proof that the application's credentials, DB
    # selection, pool, timeouts or full business transactions are healthy.
    return base
