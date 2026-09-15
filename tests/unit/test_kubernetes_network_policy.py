from pathlib import Path

import yaml


def _docs(path: str):
    return [doc for doc in yaml.safe_load_all(Path(path).read_text(encoding="utf-8")) if doc]


def test_project_does_not_ship_network_policy_ip_or_port_restrictions():
    manifests = Path("deployment/kubernetes").glob("*.yaml")
    network_policies = []
    for manifest in manifests:
        for doc in _docs(str(manifest)):
            if doc.get("kind") == "NetworkPolicy":
                network_policies.append(str(manifest))
    assert network_policies == []
    assert not Path("deployment/kubernetes/network-policy.yaml").exists()


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
