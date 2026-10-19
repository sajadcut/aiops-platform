"""Universal dependency checks never leak credentials or invent health."""
import base64
import json
import pytest
from integrations.vm.dependency_discovery import discover, load_config
from integrations.vm.dependency_investigation import investigate, http_head
from apps.context_service.dependency_signals import dependency_signals
from apps.orchestrator.dynamic_investigation import DynamicInvestigationPlanner


def test_json_services_database_broker_cache_http_secret_safe():
    data = {
        "ConnectionStrings": {"Main": "Server=sql.internal,1433;Database=Ops;Password=SECRET",
                              "Redis": "redis://user:SECRET@redis.internal:6380"},
        "ActiveMQ": {"BrokerUrl": "tcp://mq.internal:61616"},
        "RabbitMQ": {"Host": "rabbit.internal", "Port": 5671},
        "Kafka": {"BootstrapServers": "kafka01.internal:9092,kafka02.internal:9093"},
        "Payment": {"BaseUrl": "https://api.internal:8443/pay?token=SECRET"},
    }
    rows = discover(data)
    triple = {(x["kind"], x["host"], x["port"]) for x in rows}
    assert ("mssql", "sql.internal", 1433) in triple
    assert ("redis", "redis.internal", 6380) in triple
    assert ("activemq", "mq.internal", 61616) in triple
    assert ("amqp", "rabbit.internal", 5671) in triple
    assert ("kafka", "kafka01.internal", 9092) in triple
    assert ("https", "api.internal", 8443) in triple
    assert "SECRET" not in repr(rows)
    assert "pay?" not in repr(rows)
    assert len(rows) <= 8


def test_java_yaml_properties_dependencies():
    yaml_text = "spring:\n  datasource:\n    url: jdbc:postgresql://pg.internal:5433/app\n  activemq:\n    broker-url: tcp://mq.internal:61616\n"
    props = "spring.kafka.bootstrap-servers=kafka.internal:9092\nspring.datasource.url=jdbc:mysql://mysql.internal:3307/app\n"
    y = {(x["kind"], x["host"], x["port"]) for x in discover(load_config(yaml_text, "application.yml"))}
    p = {(x["kind"], x["host"], x["port"]) for x in discover(load_config(props, "application.properties"))}
    assert ("postgresql", "pg.internal", 5433) in y
    assert ("activemq", "mq.internal", 61616) in y
    assert ("kafka", "kafka.internal", 9092) in p
    assert ("mysql", "mysql.internal", 3307) in p


def test_unresolved_secret_and_unknown_db_not_probed():
    config = {"Api": {"Url": "$" + "{PAYMENT_URL}"},
              "ConnectionStrings": {"Other": "Server=%(DB_HOST)s;Database=Ops"}}
    assert discover(config) == []
    assert discover({"ActiveMQ": {"Host": "169.254.169.254", "Port": 80}}) == []


@pytest.mark.asyncio
async def test_verified_file_is_only_source_of_network_destinations():
    content = base64.b64encode(json.dumps({
        "ActiveMQ": {"BrokerUrl": "tcp://mq.internal:61616"},
        "Client": {"BaseUrl": "https://service.internal:8443/private?secret=BAD"},
        "ConnectionStrings": {"Main": "Server=sql.internal,1433;Password=BAD"},
    }).encode()).decode()

    class Stub:
        def _validate_target(self, value): assert value == "vm-a"
        def _validate_service(self, value): assert value == "gfpapi"
        def _validate_remote_host(self, value): assert value == "service.internal"
        def _validate_port(self, value): return value
        async def service_config_discovery(self, target, service):
            return {"success": True, "files": [
                {"path": "/data/gfp/appsettings.json", "verified_exists": True},
                {"path": "/etc/secret/appsettings.json", "verified_exists": False},
            ]}
        async def _run(self, target, command):
            assert "secret/appsettings" not in command
            if "curl" in command:
                assert "--head" in command and "--max-redirs 0" in command
                assert "private" not in command and "secret=" not in command
                return {"success": True, "stdout": "401 0"}
            return {"success": True, "stdout": content}
        async def tcp_check(self, target, host, port):
            return {"success": True, "supported": True, "reachable": host != "mq.internal"}

    result = await investigate(Stub(), "vm-a", "gfpapi")
    assert result["config_files_checked"] == 1
    assert result["checks_executed"] == 3
    assert result["execution_authority"] is False
    assert result["root_cause_confirmed"] is False
    assert result["protocol_health_verified"] is False
    assert "BAD" not in repr(result)
    assert any(x["kind"] == "https" and x.get("http_status") == 401
               for x in result["dependencies"])
    assert any(x["kind"] == "activemq" and x["probe_status"] == "tcp_unreachable"
               for x in result["dependencies"])


@pytest.mark.asyncio
async def test_missing_verification_never_reads_or_probes():
    class Stub:
        def _validate_target(self, value): pass
        def _validate_service(self, value): pass
        async def service_config_discovery(self, target, service):
            return {"success": True, "files": [
                {"path": "/etc/passwords.json", "verified_exists": False}]}
        async def _run(self, *args):
            raise AssertionError("config was unverified")
    result = await investigate(Stub(), "vm-a", "svc")
    assert result["status"] == "no_verified_config_files"
    assert result["checks_executed"] == 0


@pytest.mark.asyncio
async def test_http_failure_not_reported_as_success():
    class Stub:
        def _validate_remote_host(self, value): pass
        def _validate_port(self, value): return value
        async def _run(self, *args):
            return {"success": False, "stdout": "200 0"}
    result = await http_head(Stub(), "vm", host="api.internal", port=443, scheme="https")
    assert result["http_status"] is None


@pytest.mark.asyncio
async def test_planner_investigates_database_activemq_http_without_llm():
    rows = [
        {"source": "elasticsearch", "type": "log", "raw_data": {"message": "ActiveMQ broker unavailable"}},
        {"source": "zabbix", "type": "alert", "raw_data": {"message": "PostgreSQL connection timeout"}},
        {"source": "elasticsearch", "type": "log", "raw_data": {"message": "HTTP upstream 503"}},
    ]
    assert dependency_signals(rows) == ["database", "http_dependency", "message_broker"]
    result = await DynamicInvestigationPlanner.propose(
        {"service_name": "gfpapi", "context": {"evidence": rows}}, adapter=None)
    assert result["checks"] == ["dependency_investigation"]
    assert result["execution_authority"] is False
    assert DynamicInvestigationPlanner.evidence_requests(
        result, has_service=False, has_port=False) == []


def test_incident_chat_generic_intents_are_read_only():
    from apps.incident_copilot import fallback_intent, dependency_investigation_answer
    assert fallback_intent("اتصال دیتابیس رو بررسی کن") == "dependency_investigation"
    assert fallback_intent("ارتباط activemq را تست کن") == "dependency_investigation"
    assert fallback_intent("سرویس http خارجی را تست کن") == "dependency_investigation"
    answer = dependency_investigation_answer({
        "success": True, "status": "checks_completed",
        "dependencies": [{"kind": "postgresql", "host": "pg.internal", "port": 5432,
                          "probe_status": "tcp_reachable"}]})
    assert "pg.internal:5432" in answer
    assert "علت ریشه‌ای تأیید نشده" in answer


def test_tomcat_context_xml_and_dotnet_app_config_are_only_structural_sources():
    tomcat = """
    <Context>
      <Resource name="jdbc/billing" type="javax.sql.DataSource"
                url="jdbc:postgresql://pg.internal:5432/billing"
                password="DO_NOT_LOG"/>
      <Connector protocol="tcp" uri="tcp://mq.internal:61616"/>
    </Context>
    """
    config = """
    <configuration><connectionStrings>
      <add name="Billing" connectionString="Server=sql.internal,1433;Database=B;Password=SECRET"/>
    </connectionStrings></configuration>
    """
    t = discover(load_config(tomcat, "context.xml"))
    n = discover(load_config(config, "app.config"))
    assert ("postgresql", "pg.internal", 5432) in {
        (x["kind"], x["host"], x["port"]) for x in t}
    assert ("activemq", "mq.internal", 61616) in {
        (x["kind"], x["host"], x["port"]) for x in t}
    assert ("mssql", "sql.internal", 1433) in {
        (x["kind"], x["host"], x["port"]) for x in n}
    assert "SECRET" not in repr(n)
    with pytest.raises(ValueError):
        load_config("<!DOCTYPE x [<!ENTITY a 'unsafe'>]><x>&a;</x>", "context.xml")


def test_unknown_vendor_explicit_host_port_uses_generic_tcp_without_guessing():
    result = discover({"PaymentAdapter": {
        "Host": "payment.internal", "Port": "60001",
        "Password": "SHOULD_NOT_LEAK",
    }})
    assert result == [{
        "kind": "custom_tcp", "host": "payment.internal", "port": 60001,
        "port_inferred": False, "probe": "tcp", "config_verified": True,
    }]
    assert discover({"PaymentAdapter": {"Host": "payment.internal"}}) == []
    assert ("nats", "bus.internal", 4222) in {
        (x["kind"], x["host"], x["port"]) for x in
        discover({"Messaging": {"Url": "nats://bus.internal:4222"}})
    }


def test_mcp_result_contract_rejects_hidden_password_or_undeclared_fields():
    from integrations.vm.tool_contract import output_schema, validate_vm_observation
    schema = output_schema("dependency_investigation")
    assert schema["properties"]["dependencies"]["maxItems"] == 6
    base = {
        "success": True, "target": "vm01", "execution_authority": False,
        "root_cause_confirmed": False, "config_contents_exposed": False,
        "secrets_exposed": False,
        "dependencies": [{
            "kind": "postgresql", "host": "pg.internal", "port": 5432,
            "config_verified": True, "probe_status": "tcp_reachable",
        }],
    }
    assert validate_vm_observation("dependency_investigation", "vm01", base) == base
    with pytest.raises(ValueError):
        validate_vm_observation("dependency_investigation", "wrong", base)
    with pytest.raises(ValueError):
        validate_vm_observation("dependency_investigation", "vm01", {
            **base, "dependencies": [{**base["dependencies"][0], "password": "SECRET"}],
        })
    with pytest.raises(ValueError):
        validate_vm_observation("dependency_investigation", "vm01", {
            **base, "execution_authority": True,
        })
