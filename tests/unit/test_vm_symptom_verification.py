import pytest

from apps.verification_service import VerificationEngine, VerificationStatus


def _context(*items):
    return {"live_evidence": {"evidence": list(items)}}


def _telemetry(ref, diagnostic, **raw):
    return {
        "type": "telemetry",
        "source": "vm_mcp",
        "reference": ref,
        "raw_data": {"diagnostic": diagnostic, **raw},
    }


@pytest.mark.asyncio
async def test_port_recovery_is_verified_from_fresh_operational_evidence():
    before = _context(
        _telemetry("before-service", "service_status", active_state="active"),
        _telemetry("before-listener", "port_listener_status", listening=False),
        _telemetry("before-tcp", "tcp_check", reachable=False),
        _telemetry("before-config", "config_validate", valid=True),
    )
    after = _context(
        _telemetry("after-service", "service_status", active_state="active"),
        _telemetry("after-listener", "port_listener_status", listening=True),
        _telemetry("after-tcp", "tcp_check", reachable=True),
        _telemetry("after-config", "config_validate", valid=True),
    )

    result = await VerificationEngine.verify_action("reload haproxy", "haproxy", before, after)

    assert result.status == VerificationStatus.SUCCESS
    assert result.after_state["port_listening"] == 1.0
    assert result.after_state["tcp_reachable"] == 1.0
    assert "port_listening" in result.message
    assert "tcp_reachable" in result.message


@pytest.mark.asyncio
async def test_successful_command_cannot_mask_port_still_down():
    before = _context(
        _telemetry("before-service", "service_status", active_state="active"),
        _telemetry("before-listener", "port_listener_status", listening=False),
        _telemetry("before-tcp", "tcp_check", reachable=False),
    )
    after = _context(
        _telemetry("after-service", "service_status", active_state="active"),
        _telemetry("after-listener", "port_listener_status", listening=False),
        _telemetry("after-tcp", "tcp_check", reachable=False),
    )

    result = await VerificationEngine.verify_action("command exited 0", "haproxy", before, after)

    assert result.status == VerificationStatus.FAILED
    assert "port_listening" in result.message
    assert "tcp_reachable" in result.message


@pytest.mark.asyncio
async def test_invalid_config_blocks_successful_verification():
    before = _context(_telemetry("before-config", "config_validate", valid=False))
    after = _context(_telemetry("after-config", "config_validate", valid=False))

    result = await VerificationEngine.verify_action("reload haproxy", "haproxy", before, after)

    assert result.status == VerificationStatus.FAILED
    assert result.after_state["config_valid"] == 0.0
