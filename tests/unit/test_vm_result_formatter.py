from apps.chatbot.vm_result_formatter import render_vm_disk_status


def _payload():
    return {"source": "vm_mcp", "result": {"success": True, "target": "10.248.16.82", "observed_at": "2026-10-19T05:00:00Z", "filesystems": [
        {"filesystem": "/dev/sda1", "mount": "/", "blocks": "107374182400", "used": "21474836480", "available": "85899345920", "use_percent": "20%"},
        {"filesystem": "/dev/sdb1", "mount": "/app", "blocks": "214748364800", "used": "161061273600", "available": "53687091200", "use_percent": "75%"},
    ], "inodes": [
        {"mount": "/", "use_percent": "9%"},
        {"mount": "/app", "use_percent": "42%"},
    ]}}


def test_renders_every_mount_exact_free_bytes_and_inode_usage():
    message = render_vm_disk_status(_payload())
    assert "/app" in message and "/dev/sdb1" in message
    assert "50.00 GiB" in message and "75%" in message and "42%" in message
    assert "/dev/sda1" in message and "80.00 GiB" in message and "20%" in message
    assert "2026-10-19T05:00:00Z" in message


def test_failed_tool_never_claims_disk_capacity():
    result = render_vm_disk_status({"source": "vm_mcp", "result": {"success": False, "target": "vm-1", "error": "ssh_command_failed"}})
    assert "ناموفق" in result and "ssh_command_failed" in result
    assert "0.00 GiB" not in result


def test_empty_success_is_not_an_empty_successful_disk_report():
    result = render_vm_disk_status({"source": "vm_mcp", "result": {"success": True, "target": "vm-1", "filesystems": []}})
    assert "تأیید نشد" in result


def test_bad_numeric_row_is_reported_incomplete_without_guessing():
    p = _payload()
    p["result"]["filesystems"].append({"filesystem": "x", "mount": "/invalid", "blocks": "nan", "used": "1", "available": "1", "use_percent": "11%"})
    rendered = render_vm_disk_status(p)
    assert "/app" in rendered and "1 ردیف نامعتبر" in rendered
    assert "/invalid" not in rendered


def test_untrusted_disk_label_is_not_rendered_as_markup():
    p = _payload()
    p["result"]["filesystems"][0]["mount"] = "<script>alert(1)</script>"
    rendered = render_vm_disk_status(p)
    assert "<script>" not in rendered
    assert "100.00 GiB" in rendered


def test_english_and_no_timestamp_are_explicit():
    p = _payload()
    p["result"].pop("observed_at")
    answer = render_vm_disk_status(p, persian=False)
    assert "Observation timestamp not supplied" in answer
    assert "available 50.00 GiB" in answer


def test_service_inventory_display_scopes_failed_rows():
    from apps.chatbot.vm_result_formatter import render_vm_services
    p = {"source": "vm_mcp", "result": {"success": True, "target": "vm1", "scope_restricted": True,
         "matching_count": 1, "services": [
            {"name": "gfpapi.service", "active_state": "failed", "sub_state": "failed", "description": "GFP API"}]}}
    result = render_vm_services(p)
    assert "gfpapi.service" in result and "failed/failed" in result
    assert "تمام سرویس‌های میزبان نیست" in result
