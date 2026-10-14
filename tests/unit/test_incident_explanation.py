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



def test_dotnet_validator_explanation_confirms_local_aiops_parsing_not_python_on_vm():
    evidence = sample_evidence()
    evidence[-1]["raw_data"].update({
        "remote_python_required": False,
        "validator": "aiops-local-python-json-syntax-only",
        "config_contents_exposed": False,
        "config_values_persisted": False,
    })
    explained = explain_incident(evidence=evidence, service="gfpapi")
    config = explained["configuration"]
    assert config["remote_python_required"] is False
    assert config["validator_location"] == "aiops_worker"
    assert config["error_line"] == 32 and config["error_column"] == 3
    assert "کوتیشن" in config["syntax_error_fa"]
    assert explained["does_not_authorize_execution"] is True
    report = build_decision_brief(
        incident={"id": "incident-dotnet", "service": "gfpapi"},
        operator_summary={}, checkpoint={"state": {}},
        durable_evidence=evidence, findings=[], audit_events=[],
    )
    diagnostic = report["configuration_diagnostic"]
    assert diagnostic["validator_location"] == "aiops_worker"
    assert diagnostic["remote_python_required"] is False
    assert diagnostic["error_code"] == "json_property_name"
    assert report["source_policy"]["authorizes_execution"] is False


def test_old_dotnet_evidence_does_not_invent_error_type_or_remote_python_claim():
    evidence = sample_evidence()
    bad = evidence[-1]["raw_data"]["files"][0]
    bad.pop("error_code")
    bad.pop("explanation_fa")
    diagnostic = explain_incident(evidence=evidence, service="gfpapi")["configuration"]
    assert diagnostic["error_code"] == ""
    assert "نوع دقیق خطا ثبت نشده" in diagnostic["syntax_error_fa"]
    assert diagnostic["remote_python_required"] is None
    assert diagnostic["validator_location"] == "not_recorded"


def test_successful_json_syntax_names_every_real_file_with_exact_absolute_path():
    evidence = sample_evidence()
    row = evidence[-1]["raw_data"]
    row["syntax_valid"] = True
    row["status"] = "syntax_valid"
    row["files"] = [
        {"file": "appsettings.json", "status": "valid_json_syntax"},
        {"file": "appsettings.Production.json", "status": "valid_json_syntax"},
        {"file": "GFP.Endpoints.API.runtimeconfig.json", "status": "valid_json_syntax"},
    ]
    result = explain_incident(evidence=evidence, service="gfpapi")["configuration"]
    assert result["status"] == "json_syntax_valid"
    assert result["config_file"] is None  # three checked files, no arbitrary first path
    assert [(x["path"], x["status"]) for x in result["files"]] == [
        ("/data/gfp/gfpapi/appsettings.json", "valid_json_syntax"),
        ("/data/gfp/gfpapi/appsettings.Production.json", "valid_json_syntax"),
        ("/data/gfp/gfpapi/GFP.Endpoints.API.runtimeconfig.json", "valid_json_syntax"),
    ]
    assert all(x["path_verified"] for x in result["files"])
    assert all(x["evidence_ref"] == "dotnet-1" for x in result["files"])

    report = build_decision_brief(
        incident={"id": "incident-gfpapi", "service": "gfpapi", "status": "analyzing"},
        operator_summary={"observed_state": {"config_validate": {
            "valid": None, "supported": False, "config_file": "/etc/gfpapi/unknown.json",
        }}},
        checkpoint={"state": {}}, durable_evidence=evidence,
        findings=[], audit_events=[],
        now=datetime(2026, 10, 13, 14, 1, tzinfo=timezone.utc),
    )
    diagnostic = report["configuration_diagnostic"]
    assert diagnostic["status"] == "json_syntax_valid"
    assert diagnostic["config_file"] is None
    assert [x["path"] for x in diagnostic["files"]] == [
        "/data/gfp/gfpapi/appsettings.json",
        "/data/gfp/gfpapi/appsettings.Production.json",
        "/data/gfp/gfpapi/GFP.Endpoints.API.runtimeconfig.json",
    ]
    assert all(x["evidence_ref"] == "dotnet-1" for x in diagnostic["files"])
    assert "/etc/gfpapi/unknown.json" not in str(diagnostic)
    assert report["source_policy"]["authorizes_execution"] is False


def test_single_validated_json_file_sets_its_exact_path():
    evidence = sample_evidence()
    evidence[-1]["raw_data"]["syntax_valid"] = True
    evidence[-1]["raw_data"]["status"] = "syntax_valid"
    evidence[-1]["raw_data"]["files"] = [
        {"file": "appsettings.Development.json", "status": "valid_json_syntax"}
    ]
    item = explain_incident(evidence=evidence, service="gfpapi")["configuration"]
    assert item["config_file"] == "/data/gfp/gfpapi/appsettings.Development.json"
    assert item["files"][0]["path_verified"] is True


def test_no_trusted_publish_directory_reports_basename_not_guessed_path():
    evidence = sample_evidence()
    evidence[-1]["raw_data"]["syntax_valid"] = True
    evidence[-1]["raw_data"]["status"] = "syntax_valid"
    evidence[-1]["raw_data"]["publish_directory"] = "../../fake"
    evidence[-1]["raw_data"]["files"] = [
        {"file": "appsettings.json", "status": "valid_json_syntax"}
    ]
    explanation = explain_incident(evidence=evidence, service="gfpapi")
    item = explanation["configuration"]
    assert item["status"] == "json_syntax_valid"
    assert item["config_file"] is None
    assert item["files"][0]["file"] == "appsettings.json"
    assert item["files"][0]["path"] is None
    assert item["files"][0]["path_verified"] is False


def test_missing_file_metadata_does_not_claim_json_was_verified():
    evidence = sample_evidence()
    evidence[-1]["raw_data"]["syntax_valid"] = True
    evidence[-1]["raw_data"]["status"] = "syntax_valid"
    evidence[-1]["raw_data"]["files"] = []
    item = explain_incident(evidence=evidence, service="gfpapi")["configuration"]
    assert item["status"] == "unverified"
    assert item["config_file"] is None
    assert item["files"] == []


def test_partial_or_unavailable_json_file_does_not_claim_all_valid():
    evidence = sample_evidence()
    evidence[-1]["raw_data"]["syntax_valid"] = True
    evidence[-1]["raw_data"]["status"] = "partial"
    evidence[-1]["raw_data"]["files"] = [
        {"file": "appsettings.json", "status": "valid_json_syntax"},
        {"file": "appsettings.Production.json", "status": "unavailable"},
    ]
    item = explain_incident(evidence=evidence, service="gfpapi")["configuration"]
    assert item["status"] == "unverified"
    assert [x["status"] for x in item["files"]] == ["valid_json_syntax", "unavailable"]
    assert item["files"][1]["path"].endswith("appsettings.Production.json")


def test_unallowlisted_filename_is_neither_shown_nor_claimed_valid():
    evidence = sample_evidence()
    evidence[-1]["raw_data"]["syntax_valid"] = True
    evidence[-1]["raw_data"]["status"] = "syntax_valid"
    evidence[-1]["raw_data"]["files"] = [
        {"file": "passwords.json", "status": "valid_json_syntax"}
    ]
    item = explain_incident(evidence=evidence, service="gfpapi")["configuration"]
    assert item["status"] == "unverified"
    assert item["files"] == []
