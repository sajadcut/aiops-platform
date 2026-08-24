from apps.context_service.source_policy import DEFAULT_EVIDENCE_POLICY

def test_allowlisted_source():
    assert DEFAULT_EVIDENCE_POLICY.allows("zabbix")

def test_untrusted_source_is_rejected():
    assert not DEFAULT_EVIDENCE_POLICY.allows("free_text", 1.0)
