"""Secret-safe discovery of network dependencies from verified service config.

No LLM may supply a path or endpoint to this parser. Only the trusted VM
worker reads raw config; returned records contain type, hostname and port.
"""
from __future__ import annotations
import ipaddress
import json
import re
from urllib.parse import urlsplit
import yaml

MAX_ENDPOINTS = 8
HOST = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$")
HOSTPORT = re.compile(r"^(\[[0-9a-fA-F:]+\]|[A-Za-z0-9.-]+):(\d{1,5})$")
SECRET = re.compile(r"password|secret|token|credential|apikey|private", re.I)
KINDS = {
    "redis": ("redis", 6379), "postgres": ("postgresql", 5432),
    "pgsql": ("postgresql", 5432), "mysql": ("mysql", 3306),
    "mariadb": ("mysql", 3306), "sqlserver": ("mssql", 1433),
    "mssql": ("mssql", 1433), "mongodb": ("mongodb", 27017),
    "rabbitmq": ("amqp", 5672), "activemq": ("activemq", 61616),
    "artemis": ("activemq", 61616), "amqp": ("amqp", 5672),
    "kafka": ("kafka", 9092), "bootstrapservers": ("kafka", 9092),
    "elasticsearch": ("elasticsearch", 9200), "opensearch": ("elasticsearch", 9200),
    "https": ("https", 443), "http": ("http", 80),
    "memcached": ("memcached", 11211), "cassandra": ("cassandra", 9042),
    "zookeeper": ("zookeeper", 2181), "nats": ("nats", 4222),
    "mqtt": ("mqtt", 1883), "neo4j": ("neo4j", 7687),
    "etcd": ("etcd", 2379), "consul": ("consul", 8500),
}
SCHEMES = {
    "redis": "redis", "rediss": "redis", "postgres": "postgresql",
    "postgresql": "postgresql", "mysql": "mysql", "mariadb": "mysql",
    "mongodb": "mongodb", "mongodb+srv": "mongodb",
    "amqp": "amqp", "amqps": "amqp", "tcp": "activemq",
    "ssl": "activemq", "http": "http", "https": "https",
    "nats": "nats", "mqtt": "mqtt", "bolt": "neo4j",
    "cassandra": "cassandra",
}
ENDPOINT_FIELDS = {"host", "hostname", "server", "endpoint", "endpoints",
                   "address", "nodes", "url", "uri", "baseurl", "brokerurl",
                   "connection", "connectionstring", "configuration",
                   "bootstrapservers", "servers", "brokers"}


def safe_host(value):
    value = str(value or "").strip().strip("[]").rstrip(".").lower()
    if not value or len(value) > 253 or any(c in value for c in "$%{};/\\@ \t\n\r"):
        return None
    try:
        ip = ipaddress.ip_address(value)
        return None if ip.is_link_local or ip.is_multicast or ip.is_unspecified else str(ip)
    except ValueError:
        return value if HOST.fullmatch(value) and ".." not in value else None


def safe_port(value):
    if isinstance(value, bool) or not str(value).isdigit():
        return None
    result = int(value)
    return result if 1 <= result <= 65535 else None


def load_config(text: str, filename: str):
    if filename.lower().endswith(".json"):
        from integrations.vm.dotnet_local_validator import normalize_dotnet_json
        return json.loads(normalize_dotnet_json(text))
    if filename.lower().endswith((".yml", ".yaml")):
        return yaml.safe_load(text)
    if filename.lower().endswith((".xml", ".config")):
        # Tomcat context.xml and .NET app.config: only known connection
        # attribute formats are considered; no XML entities or DTD expansion.
        if "<!DOCTYPE" in text.upper() or "<!ENTITY" in text.upper():
            raise ValueError("xml_entities_not_allowed")
        import xml.etree.ElementTree as ET
        root = ET.fromstring(text)
        result = {}
        for index, element in enumerate(root.iter()):
            if index >= 75:
                break
            attrs = {str(k).lower(): v for k, v in element.attrib.items()}
            for field in ("connectionstring", "url", "uri", "brokerurl"):
                value = attrs.get(field)
                if not isinstance(value, str) or len(value) > 1600:
                    continue
                prefix = value.strip().lower()
                if prefix.startswith(("jdbc:", "server=", "host=", "data source=")):
                    result["ConnectionStrings" + str(index)] = {"ConnectionStrings": {
                        "ConnectionString": value,
                    }}
                elif prefix.startswith(("tcp://", "ssl://")):
                    result["ActiveMQ" + str(index)] = {"BrokerUrl": value}
                elif prefix.startswith(("http://", "https://")):
                    result["Service" + str(index)] = {"BaseUrl": value}
                elif prefix.startswith(("amqp://", "amqps://")):
                    result["RabbitMQ" + str(index)] = {"Connection": value}
                elif prefix.startswith(("redis://", "rediss://")):
                    result["Redis" + str(index)] = {"Configuration": value}
        return result
    if filename.lower().endswith((".properties", ".ini", ".cfg", ".conf")):
        result = {}
        for line in text.splitlines()[:1800]:
            line = line.strip()
            if not line or line.startswith(("#", ";", "!")):
                continue
            key, sep, value = line.partition("=")
            if not sep:
                key, sep, value = line.partition(":")
            if sep and len(key) <= 160 and len(value) <= 1800:
                names = [part.strip() for part in key.split(".") if part.strip()]
                if not names or len(names) > 10:
                    continue
                current = result
                for part in names[:-1]:
                    current = current.setdefault(part, {})
                    if not isinstance(current, dict):
                        break
                if isinstance(current, dict):
                    current[names[-1]] = value.strip()
        return result
    raise ValueError("unsupported_dependency_config")


def discover(config: object, limit: int = MAX_ENDPOINTS) -> list[dict]:
    output, seen = [], set()
    limit = min(MAX_ENDPOINTS, max(1, limit))

    def put(kind, hostname, port, inferred=False):
        name, number = safe_host(hostname), safe_port(port)
        if not name or not number or kind in {"unknown", "database"}:
            return
        key = (kind, name, number)
        if key not in seen and len(output) < limit:
            seen.add(key)
            output.append({
                "kind": kind, "host": name, "port": number,
                "port_inferred": inferred, "probe": (
                    "http_head" if kind in {"http", "https"} else "tcp"
                ), "config_verified": True,
            })

    def parse(value, hint):
        if not isinstance(value, str) or len(value) > 1900 or (
            "$" in value or "%" in value
        ):
            return
        value = value.strip().strip('"').strip("'")
        if value.lower().startswith("jdbc:"):
            value = value[5:]
        # SQL Server and PostgreSQL key/value connection strings.
        parts = {}
        if ";" in value and "=" in value:
            parts = {k.strip().lower(): v.strip() for fragment in value.split(";")[:20]
                     for k, sep, v in (fragment.partition("="),) if sep}
        host = parts.get("server") or parts.get("data source") or parts.get("host")
        if host:
            server, comma, port = host.partition(",")
            kind = ("mssql" if comma or "initial catalog" in parts or
                    "trusted_connection" in parts else
                    "postgresql" if "port" in parts else hint)
            explicit = safe_port(parts.get("port") or port)
            default = next((p for k, p in KINDS.values() if k == kind), None)
            put(kind, server, explicit or default, inferred=explicit is None)
            return
        if "://" in value:
            try:
                uri = urlsplit(value)
                kind = SCHEMES.get(uri.scheme.lower())
                if kind:
                    if kind == "http" and uri.scheme.lower() == "https":
                        kind = "https"
                    default = next((p for k, p in KINDS.values() if k == kind), None)
                    put(kind, uri.hostname, uri.port or default, inferred=uri.port is None)
            except ValueError:
                return
            return
        for item in value.split(",")[:8]:
            token = item.strip()
            match = HOSTPORT.fullmatch(token)
            if match:
                put(hint, match.group(1), match.group(2))
            elif hint in {v[0] for v in KINDS.values()} and "=" not in token:
                default = next((p for k, p in KINDS.values() if k == hint), None)
                put(hint, token, default, inferred=True)

    def walk(node, hint=None, depth=0):
        if depth > 8 or len(output) >= limit:
            return
        if isinstance(node, dict):
            for key, item in list(node.items())[:100]:
                name = re.sub("[^a-z0-9]", "", str(key).lower())
                if SECRET.search(name):
                    continue
                next_hint = next((kind for part, (kind, _) in KINDS.items()
                                  if part in name), hint)
                if next_hint is None and name in {
                    "baseurl", "apiurl", "serviceurl", "webhookurl", "httpurl"
                }:
                    next_hint = "http"
                # Generic application URL declarations are also legitimate
                # dependencies when backed by the same verified service file.
                if (next_hint is None and name in {
                    "url", "uri", "endpoint", "jdbcurl"
                } and isinstance(item, str)):
                    if item.startswith(("http://", "https://")):
                        next_hint = "http"
                    elif item.startswith("jdbc:"):
                        next_hint = "database"
                    elif "://" in item and item.split("://", 1)[0].lower() in SCHEMES:
                        next_hint = "custom_tcp"
                if next_hint is None and name in {"datasource", "jdbcsource"}:
                    next_hint = "database"
                if next_hint is None and name in {"connectionstring", "connectionstrings"}:
                    next_hint = "database"
                if isinstance(item, dict):
                    if next_hint != "database":
                        host = item.get("Host", item.get("host", item.get("hostname")))
                        port = item.get("Port", item.get("port"))
                        if host and port:
                            put(next_hint or "custom_tcp", host, port)
                            # The same host key must not produce a spurious
                            # additional probe on the default vendor port.
                            reduced = {k: v for k, v in item.items()
                                       if k.lower() not in {"host", "hostname"}}
                            walk(reduced, next_hint, depth + 1)
                            continue
                    walk(item, next_hint, depth + 1)
                elif isinstance(item, list):
                    for child in item[:8]:
                        walk(child, next_hint, depth + 1)
                elif isinstance(item, str) and (
                    (next_hint and (next_hint != hint or name in ENDPOINT_FIELDS))
                    or (hint == "database" and (
                        "://" in item or item.lower().startswith(
                            ("server=", "host=", "data source=")
                        )
                    ))
                ):
                    parse(item, next_hint or "database")
        elif isinstance(node, str) and hint:
            parse(node, hint)

    walk(config)
    return output
