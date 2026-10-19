"""DB, ActiveMQ and Kafka endpoints come from literal application config.

Neither the LLM nor a vendor default can supply a missing port. TCP is
read-only transport evidence, not broker/database protocol health.
"""
import base64
import json
from types import SimpleNamespace

import pytest

from integrations.vm.dependency_discovery import discover, load_config
from integrations.vm.dependency_llm_binding import resolve_llm_bindings
from integrations.vm import dependency_investigation


@pytest.mark.parametrize("filename,config,expected", [
    (
        "application.properties",
        "spring.kafka.bootstrap-servers=k1.internal:19092,k2.internal:19093\n",
        {("kafka", "k1.internal", 19092), ("kafka", "k2.internal", 19093)},
    ),
    (
        "application.yml",
        'spring:\n  activemq:\n    broker-url: "failover:(tcp://mq1.internal:61626,tcp://mq2.internal:61627)?randomize=false"\n',
        {("activemq", "mq1.internal", 61626),
         ("activemq", "mq2.internal", 61627)},
    ),
    (
        "appsettings.json",
        json.dumps({"MongoDB": {"Url": "mongodb://u:p%40ss@mongo1.internal:27018,mongo2.internal:27019/orders?replicaSet=rs0"}}),
        {("mongodb", "mongo1.internal", 27018),
         ("mongodb", "mongo2.internal", 27019)},
    ),
    (
        "application.properties",
        "spring.datasource.url=jdbc:postgresql://pg.internal:5434/app\n",
        {("postgresql", "pg.internal", 5434)},
    ),
    (
        "application.properties",
        "spring.datasource.url=jdbc:mysql://mysql.internal:3310/ops\n",
        {("mysql", "mysql.internal", 3310)},
    ),
    (
        "appsettings.json",
        json.dumps({"ConnectionStrings": {"Main": "Server=sql.internal,1439;Database=Ops;Password=mySecret"}}),
        {("mssql", "sql.internal", 1439)},
    ),
    (
        "application.properties",
        "spring.datasource.url=jdbc:oracle:thin:@//ora.internal:1528/ORCL\n",
        {("oracle", "ora.internal", 1528)},
    ),
    (
        "appsettings.json",
        json.dumps({"RabbitMQ": {"Uri": "amqps://u:p%40ss@rabbit.internal:5679/v"}}),
        {("amqp", "rabbit.internal", 5679)},
    ),
    (
        "appsettings.json",
        json.dumps({"Cassandra": {"Port": 9144, "ContactPoints": ["cass1.internal", "cass2.internal"]}}),
        {("cassandra", "cass1.internal", 9144),
         ("cassandra", "cass2.internal", 9144)},
    ),
    (
        "appsettings.json",
        json.dumps({"DataSource": {"Host": "db.internal", "Port": 5549}}),
        {("database_tcp", "db.internal", 5549)},
    ),
])
def test_all_explicit_multi_stack_port_values_are_extracted(filename, config, expected):
    rows = discover(load_config(config, filename))
    triples = {(x["kind"], x["host"], x["port"]) for x in rows
               if x["port_inferred"] is False}
    assert expected <= triples
    assert all(x["port_inferred"] is False for x in rows)
    assert "mySecret" not in str(rows)
    assert "p%40ss" not in str(rows)


class Provider:
    def __init__(self, response):
        self.response = response
        self.calls = []
    async def generate_with_messages(self, messages, **kwargs):
        self.calls.append((messages, kwargs))
        return SimpleNamespace(content=json.dumps(self.response), finish_reason="stop")


@pytest.mark.asyncio
@pytest.mark.parametrize("config,kind,host,port", [
    ({"Kafka": {"BootstrapServers": "k1.internal:19092,k2.internal:19093"}},
     "kafka", "k2.internal", 19093),
    ({"ActiveMQ": {"BrokerUrl": "failover:(tcp://mq1.internal:61626,tcp://mq2.internal:61627)"}},
     "activemq", "mq2.internal", 61627),
    ({"Postgres": {"Url": "postgresql://user:password@pg.internal:5533/ops"}},
     "postgresql", "pg.internal", 5533),
    ({"MongoDB": {"Url": "mongodb://user:password@mongo1.internal:27018,mongo2.internal:27019/app"}},
     "mongodb", "mongo2.internal", 27019),
])
async def test_llm_selects_only_preverified_inline_literals(config, kind, host, port):
    provider = Provider({"pairs": [], "endpoint_ids": ["e1" if host.endswith(("2.internal",)) else "e0"]})
    result = await resolve_llm_bindings(config, adapter=provider)
    assert result["status"] == "verified"
    assert any((e["kind"], e["host"], e["port"]) == (kind, host, port)
               for e in result["endpoints"])
    assert all(e["port_inferred"] is False for e in result["endpoints"])
    assert result["candidate_inline_endpoint_count"] >= 1
    msg = provider.calls[0][0][1]["content"]
    assert "password" not in msg and "mySecret" not in msg
    assert provider.calls[0][1]["stage"] == "dependency_config_field_binding"


@pytest.mark.asyncio
async def test_llm_cannot_invent_a_kafka_port_or_unlisted_endpoint():
    config = {"Kafka": {"BootstrapServers": "k1.internal:19092"}}
    model = Provider({"pairs": [], "endpoint_ids": ["e77"]})
    result = await resolve_llm_bindings(config, adapter=model)
    assert result["status"] == "llm_unsubstantiated_selection"
    assert not result["endpoints"]
    inline = json.loads(model.calls[0][0][1]["content"])["inline_endpoint_fields"]
    assert [entry["port"] for entry in inline] == [19092]
    assert all(entry["port"] != 9092 for entry in inline)


def test_missing_or_dns_srv_ports_are_not_confirmed():
    rows = discover({"Kafka": {"BootstrapServers": "k1.internal,k2.internal"}})
    assert rows and all(x["port_inferred"] is True for x in rows)
    assert discover({"MongoDB": {"Uri": "mongodb+srv://cluster.internal/app"}}) == []


@pytest.mark.asyncio
async def test_generic_mcp_probe_uses_nondefault_kafka_port_without_claiming_protocol(monkeypatch):
    config = {"Kafka": {"BootstrapServers": "k1.internal:19092,k2.internal:19093"}}
    encoded = base64.b64encode(json.dumps(config).encode()).decode()
    probes = []
    class Connector:
        def _validate_target(self, target): assert target == "vm"
        def _validate_service(self, service): assert service == "app"
        async def service_config_discovery(self, target, service):
            return {"success": True, "files": [{
                "path": "/srv/prod/application.json", "verified_exists": True
            }]}
        async def _run(self, target, command):
            return {"success": True, "stdout": encoded}
        async def tcp_check(self, target, host, port):
            probes.append((host, port))
            return {"success": True, "supported": True, "reachable": False}
        async def dns_check(self, *args):
            return {"success": True, "resolved": False}
    from integrations.vm import dependency_llm_binding
    async def no_llm(config):
        return await dependency_llm_binding.resolve_llm_bindings(
            config, adapter=Provider({"pairs": [], "endpoint_ids": []}))
    monkeypatch.setattr(dependency_investigation, "resolve_llm_bindings", no_llm)
    result = await dependency_investigation.investigate(Connector(), "vm", "app")
    assert set(probes) == {("k1.internal", 19092), ("k2.internal", 19093)}
    assert result["config_files_read"] == 1
    assert result["llm_field_binding_files"][0]["candidate_inline_endpoint_count"] == 2
    assert all(x["tcp_reachable"] is False for x in result["dependencies"])
    assert result["protocol_health_verified"] is False
    assert result["root_cause_confirmed"] is False
