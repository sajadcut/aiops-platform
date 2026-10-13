"""Regression: no unrelated Cognia knowledge can influence another service."""
from __future__ import annotations

import pytest

from apps.context_service.knowledge_relevance import filter_service_knowledge
from agents.shared.base import AgentInput, BaseAgent


def doc(source, content, **fields):
    return {"source_id": source, "content": content, "relevance": 99.0, **fields}


@pytest.mark.parametrize("target,other", [
    ("gfpapi", "nginx"), ("checkout", "payment"), ("orders", "redis"),
    ("auth-api", "postgres"), ("kafka", "rabbitmq"), ("backend", "haproxy"),
])
def test_cross_service_owned_knowledge_is_quarantined(target, other):
    good = doc("correct", f"Service: {target}\nSystemd troubleshooting")
    wrong = doc("wrong", f"Service: {other}\nSystemd troubleshooting")
    generic = doc("generic", "Applicability: general\nSystemd service state definitions")
    naked = doc("unowned", f"How to fix {other} on a VM")
    keep, audit = filter_service_knowledge(
        [wrong, naked, good, generic], expected_service=target,
    )
    assert [d["source_id"] for d in keep] == ["correct", "generic"]
    assert audit["rejected_count"] == 2
    assert {r["reason"] for r in audit["rejected"]} == {
        "document_service_conflicts_with_incident",
        "unscoped_document_not_verified_general",
    }


def test_scope_visibility_and_high_semantic_score_do_not_prove_applicability():
    candidate = doc("unowned", "Nginx tuning guide", scope={"type": "general"})
    kept, audit = filter_service_knowledge([candidate], expected_service="gfpapi")
    assert kept == []
    assert audit["status"] == "filtered_empty"


def test_author_declared_generic_metadata_is_allowed_but_owner_conflict_wins():
    keep, audit = filter_service_knowledge([
        doc("valid", "Generic TLS reference", metadata={"applicability": "cross-service"}),
        doc("invalid", "Service: nginx\nReference",
            metadata={"applicability": "general"}),
    ], expected_service="gfpapi")
    assert [d["source_id"] for d in keep] == ["valid"]
    assert audit["rejected_count"] == 1


def test_source_fqdn_discovery_preserved_only_for_exact_match():
    docs = [
        doc("matching", "Service: web-api\nFQDN: web.company.test\nPlatform: Kubernetes"),
        doc("other", "Service: admin-api\nFQDN: admin.company.test"),
    ]
    kept, audit = filter_service_knowledge(
        docs, expected_service=None, expected_fqdns=["web.company.test"],
    )
    assert [d["source_id"] for d in kept] == ["matching"]
    assert audit["rejected_count"] == 1


def test_unknown_host_does_not_inherit_any_service_runbook():
    kept, audit = filter_service_knowledge([
        doc("nginx", "Service: nginx\nFilesystem fix"),
        doc("postgres", "Service: postgres\nFilesystem fix"),
    ], expected_service=None)
    assert kept == []
    assert audit["rejected_count"] == 2


def test_agent_prompt_removes_legacy_unrelated_checkpoint_knowledge():
    input_data = AgentInput(
        service_name="gfpapi", evidence_summary="GFPAPI down",
        context={"knowledge_results": [
            doc("wrong", "Service: nginx\nRestart instructions"),
            doc("correct", "Service: gfpapi\nTroubleshooting"),
            doc("unowned", "An unrelated how-to"),
        ]},
    )
    assert [d["source_id"] for d in BaseAgent.knowledge_items(input_data)] == ["correct"]


def test_multiple_contradictory_service_owners_are_not_accepted():
    result, audit = filter_service_knowledge([
        doc("conflict", "Service: gfpapi\nGuide",
            metadata={"service": "nginx"}),
    ], expected_service="gfpapi")
    assert result == []
    assert audit["rejected_count"] == 1
