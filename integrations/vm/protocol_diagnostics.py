"""Read-only protocol diagnostics for independently verified application dependencies.

A protocol probe runs only on the *consumer VM* for an endpoint parsed from a
systemd-bound config file. No credentials or application URL paths are used.
stdout/stderr remain inside the trusted worker; only enumerated statuses escape.
"""
from __future__ import annotations

import shlex
from typing import Any


async def redis_unauthenticated_ping(
    connector: Any, target: str, host: str, port: int, *, tls: bool = False,
) -> dict:
    """Best-effort unauthenticated PING; never claims the application can log in.

    An AUTH-required response means the Redis protocol answered; it is not
    evidence of incorrect credentials. The worker never issues AUTH, SELECT,
    CONFIG, FLUSH or any write or key-reading command.
    """
    connector._validate_target(target)
    connector._validate_remote_host(host)
    checked_port = connector._validate_port(port)
    if type(tls) is not bool:
        raise ValueError("redis_tls_flag_invalid")
    cmd = (
        "if ! command -v redis-cli >/dev/null 2>&1 "
        "|| ! command -v timeout >/dev/null 2>&1; "
        "then printf '__AIOPS_REDIS_CLI_UNAVAILABLE__'; "
        "else timeout 5 redis-cli --raw --no-auth-warning "
        "-h " + shlex.quote(host) + " -p " + str(checked_port)
        + (" --tls" if tls else "")
        + " PING 2>&1 | head -c 256; fi"
    )
    try:
        response = await connector._run(target, cmd)
        if response.get("success") is not True:
            return {"protocol_status": "probe_unavailable",
                    "protocol_supported": False,
                    "protocol_health_verified": False}
        output = str(response.get("stdout") or "").strip().lower()
    except Exception:
        return {"protocol_status": "probe_unavailable",
                "protocol_supported": False,
                "protocol_health_verified": False}
    if "__aiops_redis_cli_unavailable__" in output:
        status = "client_not_installed"
    elif output == "pong":
        status = "unauthenticated_ping_ok"
    elif "noauth" in output or "authentication required" in output:
        status = "authentication_required"
    elif "noperm" in output:
        status = "access_denied"
    elif "ssl" in output or "tls" in output or "certificate" in output:
        status = "tls_handshake_unverified"
    else:
        status = "protocol_unverified"
    return {
        "protocol_status": status,
        "protocol_supported": status not in {
            "client_not_installed", "protocol_unverified",
        },
        "protocol_health_verified": status == "unauthenticated_ping_ok",
    }
