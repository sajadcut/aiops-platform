from pathlib import Path

from integrations.kubernetes.client import KubernetesEvidenceClient


def test_kubernetes_connector_source_has_no_write_http_verbs():
    source = Path("integrations/kubernetes/client.py").read_text(encoding="utf-8")
    assert ".post(" not in source
    assert ".put(" not in source
    assert ".patch(" not in source
    assert ".delete(" not in source
    assert "client.get(" in source


def test_kubernetes_connector_can_be_disabled_without_network(monkeypatch):
    from domain.contracts.config import settings
    monkeypatch.setattr(settings, "KUBERNETES_API_URL", None)
    client = KubernetesEvidenceClient()
    assert client.enabled is False


def test_kubernetes_env_contract_is_centralized():
    text = Path(".env.example").read_text(encoding="utf-8")
    for key in [
        "KUBERNETES_API_URL",
        "KUBERNETES_TOKEN",
        "KUBERNETES_TOKEN_FILE",
        "KUBERNETES_CA_CERT_PATH",
        "KUBERNETES_NAMESPACE",
        "KUBERNETES_TIMEOUT_SECONDS",
        "KUBERNETES_LOG_TAIL_LINES",
    ]:
        assert f"{key}=" in text
