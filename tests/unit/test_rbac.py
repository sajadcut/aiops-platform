from apps.security.rbac import allowed

def test_viewer_cannot_approve():
    assert not allowed("viewer", "approve:low_risk")

def test_sre_can_approve_high_risk():
    assert allowed("sre", "approve:high_risk")
