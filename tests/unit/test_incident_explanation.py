"""Real VM facts must dominate unsupported checks, historical suggestions, and model claims."""
from datetime import datetime, timezone

from apps.incident_explanation import explain_incident
from apps.decision_brief import build_decision_brief


def sample_evidence():
    stamp = datetime(2026, 10, 13, 14, 0, tzinfo=timezone.utc).isoformat()
    return [
        {"id": "service-1", "source": "vm_mcp", "created_at": stamp,
         "raw_data": {"diagnostic": "service_status", "service": "gfpapi",
                      "success": True, "active_state": "failed", "result": "timeout"}},
        {"id": "generic-unsupported", "source": "vm_mcp", "created_at": stamp,
         "raw_data": {"diagnostic": "config_validate", "service": "gfpapi",
                      "success": True, "supported": False, "valid": None}},
        {"id": "dotnet-1", "source": "vm_mcp", "created_at": stamp,
         "raw_data": {"diagnostic": "dotnet_config_syntax", "service": "gfpapi",
                      "success": True, "supported": True, "syntax_valid": False,
                      "status": "invalid", "publish_directory": "/data/gfp/gfpapi",
                      "files": [
                          {"file": "appsettings.json", "status": "invalid_json_syntax",
                           "line": 32, "column": 3,
                           "error_code": "json_property_name",
                           "explanation_fa": "نام کلید باید داخل کوتیشن دوتایی باشد؛ ویرگول اضافهٔ خط قبل را بررسی کنید."},
                          {"file": "GFP.Endpoints.API.runtimeconfig.json",
                           "status": "valid_json_syntax"}]}},
    ]


def test_operator_reads_exact_dotnet_error_without_server_logs_or_llm():
    explanation = explain_incident(evidence=sample_evidence(), service="gfpapi")
    diagnostic = explanation["configuration"]
    assert diagnostic["status"] == "invalid"
    assert diagnostic["config_file"] == "/data/gfp/gfpapi/appsettings.json"
    assert diagnostic["error_line"] == 32
    assert diagnostic["error_column"] == 3
    assert diagnostic["error_code"] == "json_property_name"
    assert diagnostic["evidence_refs"] == ["dotnet-1"]
    assert explanation["does_not_authorize_execution"] is True
    assert any("علت توقف" in message for message in explanation["uncertainties_fa"])
    assert any("تأیید" in step for step in explanation["next_steps_fa"])
    assert not any("روش عمومی اعتبارسنجی" in x for x in explanation["uncertainties_fa"])


def test_brief_prioritizes_specialized_invalid_json_over_generic_unsupported():
    evidence = sample_evidence()
    report = build_decision_brief(
        incident={"id": "incident-gfpapi", "service": "gfpapi", "status": "analyzing"},
        operator_summary={"observed_state": {"config_validate": {
            "supported": False, "valid": None, "evidence_id": "generic-unsupported",
        }}},
        checkpoint={"state": {"evaluation": {"confidence": .64, "decision": "blocked"},
                               "coordination": {"agreement_score": .36}}, "version": 4},
        durable_evidence=evidence, findings=[], audit_events=[],
        now=datetime(2026, 10, 13, 14, 1, tzinfo=timezone.utc),
    )
    diagnostic = report["configuration_diagnostic"]
    assert diagnostic["status"] == "invalid"
    assert diagnostic["config_file"] == "/data/gfp/gfpapi/appsettings.json"
    assert diagnostic["error_line"] == 32
    assert diagnostic["error_column"] == 3
    assert diagnostic["error_code"] == "json_property_name"
    assert "dotnet-1" in diagnostic["evidence_refs"]
    assert report["incident_summary"]["total_evidence_count"] == 3
    assert "خطای معتبر" in report["operator_explanation"]["headline_fa"]
    assert report["source_policy"]["authorizes_execution"] is False


def test_unverified_dotnet_result_is_not_said_to_be_valid_or_invalid():
    rows = sample_evidence()
    rows[-1]["raw_data"]["supported"] = False
    rows[-1]["raw_data"]["success"] = False
    result = explain_incident(evidence=rows, service="gfpapi")
    assert result["configuration"] is None
    assert not any("نامعتبر" in x["text_fa"] for x in result["confirmed_findings"])


def test_json_syntax_valid_cannot_grant_start_or_semantic_health():
    rows = sample_evidence()
    rows[-1]["raw_data"]["syntax_valid"] = True
    rows[-1]["raw_data"]["status"] = "syntax_valid"
    rows[-1]["raw_data"]["files"] = [
        {"file": "appsettings.json", "status": "valid_json_syntax"}
    ]
    result = explain_incident(evidence=rows, service="gfpapi")
    assert result["configuration"]["status"] == "json_syntax_valid"
    assert result["does_not_authorize_execution"] is True
    assert "در حال حاضر" in result["approval_explanation_fa"]
