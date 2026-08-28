from pathlib import Path

import yaml


def _docs(path: str):
    return [doc for doc in yaml.safe_load_all(Path(path).read_text(encoding="utf-8")) if doc]


def test_network_policy_defaults_to_deny_and_only_allows_labeled_namespaces():
    policies = _docs("deployment/kubernetes/network-policy.yaml")
    assert len(policies) == 2
    deny, allow = policies
    assert deny["kind"] == "NetworkPolicy"
    assert set(deny["spec"]["policyTypes"]) == {"Ingress", "Egress"}
    assert "ingress" not in deny["spec"]
    assert "egress" not in deny["spec"]

    ingress = allow["spec"]["ingress"][0]
    assert ingress["ports"] == [{"protocol": "TCP", "port": 8000}]
    assert ingress["from"][0]["namespaceSelector"]["matchLabels"]["aiops.network/ingress"] == "allowed"

    egress = allow["spec"]["egress"]
    assert {item["port"] for rule in egress for item in rule["ports"]} == {53, 443, 5432}
    allowed_labels = [rule["to"][0]["namespaceSelector"]["matchLabels"] for rule in egress]
    assert {"kubernetes.io/metadata.name": "kube-system"} in allowed_labels
    assert {"aiops.network/egress": "allowed"} in allowed_labels


def test_production_deployment_uses_stdout_not_ephemeral_log_volume():
    deployment = next(doc for doc in _docs("deployment/kubernetes/aiops-platform.yaml") if doc.get("kind") == "Deployment")
    pod = deployment["spec"]["template"]["spec"]
    container = pod["containers"][0]
    env = {item["name"]: item["value"] for item in container["env"]}
    assert env["LOG_CONSOLE_ENABLED"] == "true"
    assert env["LOG_TEXT_FILE_ENABLED"] == "false"
    assert env["LOG_JSON_FILE_ENABLED"] == "false"
    assert all(volume["name"] != "logs" for volume in pod.get("volumes", []))
    assert all(mount["name"] != "logs" for mount in container.get("volumeMounts", []))
