from apps.context_service.knowledge_topology import KnowledgeTopologyResolver


def _doc(url: str = "https://web.wepod.ir/app"):
    return {
        "id": "cognia:topology:web",
        "source_id": "cognia:topology:web",
        "content": (
            "Service: web-api\n"
            f"Public URL: {url}\n"
            "Platform: Kubernetes\n"
            "Namespace: wepod-prod\n"
        ),
    }


def test_expected_full_url_is_normalized_before_matching_cognia_topology():
    topology = KnowledgeTopologyResolver.resolve(
        [_doc()],
        expected_fqdns=["HTTPS://WEB.WEPOD.IR:443/health?check=1"],
    )

    assert topology["fields"]["fqdn"] == "web.wepod.ir"
    assert topology["fields"]["service"] == "web-api"
    assert topology["fields"]["namespace"] == "wepod-prod"
    assert topology["skipped_mismatched_fqdns"] == []


def test_normalized_expected_url_still_rejects_other_cognia_fqdn():
    topology = KnowledgeTopologyResolver.resolve(
        [_doc("https://admin.wepod.ir")],
        expected_fqdns=["https://web.wepod.ir/status"],
    )

    assert topology["fields"] == {}
    assert topology["skipped_mismatched_fqdns"] == ["admin.wepod.ir"]
