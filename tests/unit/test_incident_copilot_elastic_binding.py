"""Incident Copilot: proof of Elasticsearch provenance and VM target recovery."""
import json
from datetime import datetime, timezone, timedelta
from types import SimpleNamespace
from uuid import UUID

import pytest

from apps.incident_copilot import fallback_intent, merge_incident_evidence, vm_binding
from apps.incident_elastic import (
    elastic_answer, elastic_live_read, stored_elastic_observations,
)


def vm_row(action="service_status", target="10.248.16.82", service="gfpapi",
           success=True, ref="vm:service:1", **extra):
    return {
        "source": "vm_mcp", "reference": ref,
        "raw_data": {
            "diagnostic": action, "target": target, "service": service,
            "success": success, **extra,
        },
    }


def stored_elastic(service="gfpapi", status="queried", count=12):
    return {
        "source": "elasticsearch", "reference": "elastic-observation:1",
        "raw_data": {
            "service": service, "status": status, "result_count": count,
            "detail": "matching_logs",
        },
    }


def test_vm_status_survives_recent_db_limit_via_same_incident_checkpoint():
    checkpoint = {"state": {"live_evidence": {"evidence": [
        vm_row(active_state="failed", result="timeout"),
    ]}, "context": {}}}
    restored = merge_incident_evidence(
        [stored_elastic(), {"source": "zabbix", "raw_data": {"service": "gfpapi"}}],
        checkpoint,
    )
    bound = vm_binding("gfpapi", restored)
    assert bound["service"] == "gfpapi"
    assert bound["target"] == "10.248.16.82"
    assert bound["verification"] == "service_status"
    assert bound["evidence_refs"] == ["vm:service:1"]


def test_vm_fallback_uses_two_real_diagnostics_never_one_claim():
    config = vm_row("config_validate", ref="config1", supported=False, valid=None)
    process = vm_row("process_status", ref="process1", running=False)
    assert vm_binding("gfpapi", [config]) is None
    assert vm_binding("gfpapi", [config, process])["verification"] == "multiple_vm_diagnostics"
    assert vm_binding("gfpapi", [config, vm_row(target="10.248.16.83")]) is None
    assert vm_binding("gfpapi", [config, process], {
        "trigger_signal": {"payload": {"service": "another", "target_ip": "10.248.16.82"}}
    }) is None
    assert vm_binding("gfpapi", [config, process], {
        "service_identity": {"conflicts": [{"field": "target"}]},
    }) is None


@pytest.mark.parametrize("text,intent", [
    ("نتیجه بررسی در الستیک چی بوده؟", "elastic_recorded"),
    ("استعلام mcp الستیک چی؟", "elastic_logs"),
    ("ELK logs now", "elastic_logs"),
    ("what did Elasticsearch find?", "elastic_recorded"),
    ("یه ریلود بکن سرویس رو", "propose_reload"),
    ("من مالک سرویسم استارتش کن", "propose_start"),
])
def test_elastic_and_explicit_operator_intents(text,intent):
    assert fallback_intent(text) == intent


def test_elasticsearch_facts_cannot_be_inferred_from_vm_journal():
    mixed = [
        {"source": "vm_mcp", "reference": "vm:service_logs", "raw_data": {
            "diagnostic": "service_logs", "service": "gfpapi",
            "logs": ["chat-server connected", "HTTP 401"]}},
        stored_elastic(count=4),
        {"source": "elasticsearch", "raw_data": {
            "service": "some-other-app", "status": "queried", "result_count": 23}},
    ]
    result = stored_elastic_observations(mixed, service="gfpapi")
    assert result["recorded_count"] == 4
    assert result["sampled_log_evidence_count"] == 0
    assert result["source"] == "elasticsearch"
    assert "401" not in elastic_answer(result)
    missing = stored_elastic_observations(mixed[:1], service="gfpapi")
    assert missing["status"] == "not_recorded"
    assert "systemd" in elastic_answer(missing)
    log_only = stored_elastic_observations([{
        "source": "elasticsearch", "reference": "log:1", "raw_data": {
            "service": "gfpapi", "message": "application timeout",
        },
    }], service="gfpapi")
    assert log_only["status"] == "log_evidence_only"
    assert log_only["sampled_log_evidence_count"] == 1
    assert "تعداد کل" in elastic_answer(log_only)


@pytest.mark.asyncio
async def test_live_elastic_queries_same_service_bounded_window_and_provenance():
    now = datetime(2026,10,13,16,00,tzinfo=timezone.utc)
    calls = []
    class Elastic:
        async def get_logs(self, service, since, until, limit):
            calls.append((service, since, until, limit))
            return [
                SimpleNamespace(timestamp=now, level="error",
                                message="connection timed out"),
                SimpleNamespace(timestamp=now, level="info",
                                message="request received"),
            ]
    result = await elastic_live_read(
        "gfpapi", incident_started_at=now-timedelta(hours=20),
        connector=Elastic(), clock=now,
    )
    assert calls == [("gfpapi", now-timedelta(hours=6), now, 40)]
    assert result["success"] is True
    assert result["source"] == "elasticsearch"
    assert result["returned_count"] == 2
    assert result["levels"] == {"error":1,"info":1}
    assert "connection timed out" in elastic_answer(result)
    assert result["absence_of_errors_proven"] is False


@pytest.mark.asyncio
async def test_elastic_transport_failure_is_not_disguised_as_mcp_success():
    class Elastic:
        async def get_logs(self, *args, **kwargs):
            raise TimeoutError("private endpoint info must not leak")
    result = await elastic_live_read("gfpapi", connector=Elastic())
    assert result["success"] is False
    assert result["status"] == "elastic_mcp_unavailable"
    assert "private endpoint" not in json.dumps(result)
    assert "ناموفق" in elastic_answer(result)


@pytest.mark.asyncio
async def test_explicit_gfpapi_start_proposes_same_incident_action_even_when_llm_says_reload(monkeypatch):
    import apps.api.incident_chat as api
    incident_id = UUID("11111111-1111-4111-8111-111111111111")
    calls = []
    class DB:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
    class Audit:
        def __init__(self, db): pass
        async def list(self, *a): return []
    async def scope(db, incident):
        saved = merge_incident_evidence(
            [], {"state": {"live_evidence":{"evidence":[vm_row(active_state="failed")]} }}
        )
        return SimpleNamespace(service="gfpapi", started_at=datetime.now(timezone.utc)), {
            "state":{"context":{}},
        }, saved
    async def brief(db, iid): return {"incident_summary":{"service":"gfpapi"}}
    async def model(*a, **kw):
        return {"intent":"propose_reload", "answer":"reload immediately", "reason":"",
                "model_status":"structured"}
    async def append(*a,**kw):
        calls.append(kw)
        return "turn-1"
    monkeypatch.setattr(api,"AsyncSessionLocal",DB)
    monkeypatch.setattr(api,"_scope",scope)
    monkeypatch.setattr(api,"PostgreSQLAuditStore",Audit)
    monkeypatch.setattr(api,"load_decision_brief_for_incident",brief)
    monkeypatch.setattr(api,"llm_plan",model)
    monkeypatch.setattr(api,"append_turn",append)
    output = await api.incident_chat_message(
        incident_id, api.IncidentChatMessage(message="من مالک سرویسم استارتش کن"),
        identity=SimpleNamespace(subject="operator"),
    )
    assert output["kind"] == "action_proposal"
    assert output["proposal"]["action"] == "start_service"
    assert output["proposal"]["target"] == "10.248.16.82"
    assert output["proposal"]["execution_authority"] is False
    assert calls[-1]["role"] == "assistant"


@pytest.mark.asyncio
async def test_incident_elastic_historical_answer_never_invokes_live_mcp(monkeypatch):
    import apps.api.incident_chat as api
    incident_id = UUID("11111111-1111-4111-8111-111111111111")
    calls = []
    class DB:
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
    class Audit:
        def __init__(self,db): pass
        async def list(self,*a): return []
        async def append(self,e): calls.append(e["event_type"])
    async def scope(db,iid):
        return SimpleNamespace(service="gfpapi",started_at=datetime.now(timezone.utc)), {
            "state":{"context":{}},
        }, [stored_elastic(count=7)]
    async def brief(db,iid): return {"incident_summary":{"service":"gfpapi"}}
    async def model(*a,**kw):
        return {"intent":"answer", "answer":"Elastic logs show no 401/403",
                "reason":"", "model_status":"structured"}
    async def elastic(*a,**kw):
        raise AssertionError("Historical question must never call live Elastic")
    async def append(*a,**kw): return "audit-1"
    monkeypatch.setattr(api,"AsyncSessionLocal",DB)
    monkeypatch.setattr(api,"_scope",scope)
    monkeypatch.setattr(api,"PostgreSQLAuditStore",Audit)
    monkeypatch.setattr(api,"load_decision_brief_for_incident",brief)
    monkeypatch.setattr(api,"llm_plan",model)
    monkeypatch.setattr(api,"elastic_live_read",elastic)
    monkeypatch.setattr(api,"append_turn",append)
    output=await api.incident_chat_message(
        incident_id,api.IncidentChatMessage(message="نتیجه بررسی در الستیک چی بوده"),
        identity=SimpleNamespace(subject="operator"),
    )
    assert output["answer_basis"]=="stored_elasticsearch_evidence"
    assert "7" in output["message"]
    assert "401" not in output["message"]
    assert "incident_copilot_read" in calls


@pytest.mark.asyncio
async def test_explicit_elastic_mcp_query_not_vm_and_model_fallback_has_facts(monkeypatch):
    import apps.api.incident_chat as api
    incident_id = UUID("11111111-1111-4111-8111-111111111111")
    calls=[]
    class DB:
        async def __aenter__(self): return self
        async def __aexit__(self,*a): return False
    class Audit:
        def __init__(self,db): pass
        async def list(self,*a): return []
        async def append(self,event): calls.append(event["event_type"])
    async def scope(db, iid):
        return SimpleNamespace(service="gfpapi",started_at=datetime.now(timezone.utc)), {"state":{"context":{}}}, []
    async def brief(db,iid): return {"incident_summary":{"service":"gfpapi"}}
    async def model(*args,**kwargs):
        return {"intent":"answer","answer":"", "reason":"", "model_status":"unavailable"}
    async def elastic(service,**kwargs):
        calls.append("elastic_live")
        return {
            "success":True,"source":"elasticsearch","status":"queried",
            "is_live":True,"searched_service":service,
            "from":"2026-10-13T15:00:00+00:00","until":"2026-10-13T16:00:00+00:00",
            "returned_count":1,"levels":{"error":1},
            "results":[{"time":"2026-10-13T15:42:00+00:00","level":"error",
                        "message":"timeout connecting upstream"}],
        }
    async def append(*a,**kw):return "audit-2"
    monkeypatch.setattr(api,"AsyncSessionLocal",DB)
    monkeypatch.setattr(api,"_scope",scope)
    monkeypatch.setattr(api,"PostgreSQLAuditStore",Audit)
    monkeypatch.setattr(api,"load_decision_brief_for_incident",brief)
    monkeypatch.setattr(api,"llm_plan",model)
    monkeypatch.setattr(api,"elastic_live_read",elastic)
    monkeypatch.setattr(api,"append_turn",append)
    output=await api.incident_chat_message(
        incident_id,api.IncidentChatMessage(message="استعلام mcp الستیک چی"),
        identity=SimpleNamespace(subject="operator"),
    )
    assert "elastic_live" in calls
    assert output["answer_basis"]=="live_elasticsearch_mcp"
    assert output["model_status"]=="unavailable"
    assert "timeout connecting upstream" in output["message"]
    assert "نتیجه را در شواهد" not in output["message"]


def test_incident_ui_distinguishes_elastic_sources():
    from pathlib import Path
    ui=Path("dashboards/incident-command-room.js").read_text(encoding="utf-8")
    assert "stored_elasticsearch_evidence" in ui
    assert "live_elasticsearch_mcp" in ui
    assert "elastic_mcp_unavailable" in ui


@pytest.mark.asyncio
async def test_llm_cannot_claim_no_401_or_403_on_unverified_elastic_evidence(monkeypatch):
    import apps.api.incident_chat as api
    incident_id = UUID("11111111-1111-4111-8111-111111111111")
    class DB:
        async def __aenter__(self):return self
        async def __aexit__(self,*a):return False
    class Audit:
        def __init__(self, db):pass
        async def list(self,*a):return []
    async def scope(db,iid):
        return SimpleNamespace(service="gfpapi",started_at=datetime.now(timezone.utc)), {"state":{"context":{}}}, [vm_row(active_state="failed")]
    async def brief(db,iid):
        return {"incident_summary":{"service":"gfpapi"}, "mcp_evidence":[{
            "tool":"service_status","status":"success",
            "finding":"active_state=failed; result=timeout","evidence_ref":"vm:service:1",
        }]}
    async def model(*args,**kwargs):
        return {"intent":"answer",
                "answer":"هیچ خطای HTTP 401 یا 403 در لاگ‌ها مشاهده نشده و مشکل احراز هویت رد شده است.",
                "model_status":"structured"}
    async def append(*args,**kwargs):return "turn-id"
    monkeypatch.setattr(api,"AsyncSessionLocal",DB)
    monkeypatch.setattr(api,"_scope",scope)
    monkeypatch.setattr(api,"PostgreSQLAuditStore",Audit)
    monkeypatch.setattr(api,"load_decision_brief_for_incident",brief)
    monkeypatch.setattr(api,"llm_plan",model)
    monkeypatch.setattr(api,"append_turn",append)
    output=await api.incident_chat_message(
        incident_id, api.IncidentChatMessage(message="مشکل چیه"),
        identity=SimpleNamespace(subject="operator"),
    )
    assert output["answer_basis"]=="stored_analysis_guarded"
    assert "مشاهده نشده" not in output["message"]
    assert "رد شده است" not in output["message"]
    assert "اثبات نمی‌شود" in output["message"]
    assert "active_state=failed" in output["message"]
