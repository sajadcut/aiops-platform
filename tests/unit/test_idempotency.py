from domain.idempotency import request_fingerprint

def test_fingerprint_is_stable():
    a = request_fingerprint({"action": "check", "target": "svc", "parameters": {"b": 2, "a": 1}})
    b = request_fingerprint({"parameters": {"a": 1, "b": 2}, "target": "svc", "action": "check"})
    assert a == b
