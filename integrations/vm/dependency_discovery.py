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
    "oracle": ("oracle", 1521), "db2": ("db2", 50000),
    "rabbitmq": ("amqp", 5672), "activemq": ("activemq", 61616),
    "artemis": ("activemq", 61616), "amqp": ("amqp", 5672),
    "kafka": ("kafka", 9092), "bootstrapservers": ("kafka", 9092),
    "elasticsearch": ("elasticsearch", 9200), "opensearch": ("elasticsearch", 9200),
    "https": ("https", 443), "http": ("http", 80),
    "memcached": ("memcached", 11211), "cassandra": ("cassandra", 9042),
    "zookeeper": ("zookeeper", 2181), "nats": ("nats", 4222),
    "mqtt": ("mqtt", 1883), "neo4j": ("neo4j", 7687),
    "etcd": ("etcd", 2379), "consul": ("consul", 8500),
    # Technology-neutral database config; never guess the server protocol.
    "datasource": ("database_tcp", None), "r2dbc": ("database_tcp", None),
    "jdbc": ("database_tcp", None), "dbconnection": ("database_tcp", None),
    "database": ("database_tcp", None),
}
SCHEMES = {
    "redis": "redis", "rediss": "redis", "postgres": "postgresql",
    "postgresql": "postgresql", "mysql": "mysql", "mariadb": "mysql",
    "mongodb": "mongodb", "mongodb+srv": "mongodb",
    "sqlserver": "mssql", "oracle": "oracle", "db2": "db2",
    "amqp": "amqp", "amqps": "amqp", "tcp": "custom_tcp",
    "ssl": "custom_tcp", "http": "http", "https": "https",
    "nats": "nats", "mqtt": "mqtt", "mqtts": "mqtt",
    "kafka": "kafka", "elasticsearch": "elasticsearch",
    "opensearch": "elasticsearch", "memcached": "memcached",
    "bolt": "neo4j", "cassandra": "cassandra",
}
ENDPOINT_FIELDS = {"host", "hostname", "server", "endpoint", "endpoints",
                   "address", "nodes", "url", "uri", "baseurl", "brokerurl",
                   "connection", "connectionstring", "configuration",
                   "bootstrapservers", "contactpoints", "seednodes", "servers", "brokers", "primary", "secondary",
                   "master", "replica", "connectionstring"}


_CONFIG_KEY_PART = re.compile(r"^[A-Za-z_][A-Za-z0-9_-]{0,49}$")


def safe_config_key(parts: tuple[str, ...]) -> str | None:
    """Structural key provenance only; never return arbitrary config key/value."""
    if not parts or len(parts) > 10:
        return None
    if any(not _CONFIG_KEY_PART.fullmatch(p) or SECRET.search(p) for p in parts):
        return None
    result = ".".join(parts)
    return result if len(result) <= 160 else None


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
    if filename.lower().endswith(".toml"):
        # Python standard library; important for Go and Python services.
        import tomllib
        return tomllib.loads(text)
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
    if filename.lower().endswith((".properties", ".ini", ".cfg", ".conf", ".cnf")):
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

    def put(kind, hostname, port, inferred=False, source_key=None, tls_requested=False):
        name, number = safe_host(hostname), safe_port(port)
        if not name or not number or kind in {"unknown", "database"}:
            return
        key = (kind, name, number)
        if key not in seen and len(output) < limit:
            seen.add(key)
            record = {
                "kind": kind, "host": name, "port": number,
                "port_inferred": inferred, "probe": (
                    "http_head" if kind in {"http", "https"} else "tcp"
                ), "config_verified": True,
            }
            if source_key:
                record["config_key"] = source_key
            if kind == "redis":
                record["tls_requested"] = tls_requested is True
            output.append(record)

    def parse(value, hint, source_key=None, explicit_port=None):
        if not isinstance(value, str) or len(value) > 1900:
            return
        # Reject unresolved placeholders in the destination itself below.
        # Credential punctuation is allowed; no credential value is returned.
        value = value.strip().strip('"').strip("'")
        # StackExchange.Redis option ssl=true is a hint, not proof of TLS.
        redis_tls = bool(re.search(r"(?:^|,)\s*ssl\s*=\s*true(?:,|$)", value, re.I))
        if value.lower().startswith("jdbc:"):
            value = value[5:]
        # ActiveMQ/OpenWire supports failover:(tcp://a:61616,tcp://b:61617).
        # A single urlsplit() on the outer failover scheme loses all brokers.
        if value.lower().startswith("failover:("):
            inner, sep, _ = value[len("failover:("):].partition(")")
            if not sep:
                return
            for target in inner.split(",")[:8]:
                parse(target.strip(), hint or "activemq", source_key)
            return
        # MongoDB replica sets use comma-separated hosts in one URI.
        # Extract authority only, never the username, password or database.
        if value.lower().startswith(("mongodb://", "mongodb+srv://")):
            scheme, tail = value.split("://", 1)
            authority = tail.split("/", 1)[0].split("?", 1)[0].rsplit("@", 1)[-1]
            for peer in authority.split(",")[:8]:
                peer = peer.strip()
                try:
                    parsed_peer = urlsplit("mongodb://" + peer)
                    explicit = parsed_peer.port
                    if scheme.lower() == "mongodb+srv":
                        # SRV records are DNS-discovered, not configured TCP
                        # ports. No default port may be verified by TCP here.
                        continue
                    put("mongodb", parsed_peer.hostname, explicit or 27017,
                        inferred=explicit is None, source_key=source_key)
                except ValueError:
                    continue
            return
        # Oracle JDBC Thin has a vendor-specific prefix rather than a URI.
        if value.lower().startswith("oracle:thin:@//"):
            value = "oracle://" + value[len("oracle:thin:@//"):]
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
                    hint if hint not in {None, "database"} else
                    "custom_tcp" if ("port" in parts or port) else "database")
            explicit = safe_port(parts.get("port") or port)
            default = next((p for k, p in KINDS.values() if k == kind), None)
            # Server/Port can be separate connection-string properties.
            # A missing explicit value remains *inferred*, never tested.
            if explicit is not None or default is not None:
                put(kind, server, explicit if explicit is not None else default,
                    inferred=explicit is None, source_key=source_key)
            return
        if "://" in value:
            try:
                # SQL Server JDBC semicolon properties are not part of host:port.
                uri = urlsplit(value.split(";", 1)[0] if value.lower().startswith(
                    "sqlserver://") else value)
                scheme = uri.scheme.lower()
                kind = SCHEMES.get(scheme)
                # tcp:// and ssl:// are generic transports. Only a verified
                # ActiveMQ/Artemis context may identify them as ActiveMQ.
                if scheme in {"tcp", "ssl"}:
                    kind = hint if hint in {"activemq", "amqp", "kafka", "nats",
                                            "mqtt", "redis"} else "custom_tcp"
                if kind:
                    default = next((p for k, p in KINDS.values() if k == kind), None)
                    if scheme == "amqps":
                        default = 5671
                    if scheme == "mqtts":
                        default = 8883
                    port = uri.port
                    put(kind, uri.hostname, port if port is not None else default,
                        inferred=port is None, source_key=source_key,
                        tls_requested=(kind == "redis" and scheme == "rediss"))
            except ValueError:
                return
            return
        for item in value.split(",")[:8]:
            token = item.strip()
            match = HOSTPORT.fullmatch(token)
            if match:
                put(hint, match.group(1), match.group(2), source_key=source_key,
                    tls_requested=(hint == "redis" and redis_tls))
            elif hint in {v[0] for v in KINDS.values()} and "=" not in token:
                default = next((p for k, p in KINDS.values() if k == hint), None)
                port = explicit_port if explicit_port is not None else default
                put(hint, token, port, inferred=explicit_port is None, source_key=source_key,
                    tls_requested=(hint == "redis" and redis_tls))

    def walk(node, hint=None, depth=0, keypath=(), inherited_port=None):
        if depth > 8 or len(output) >= limit:
            return
        if isinstance(node, dict):
            # Host and Port can live in the same object or its Redis/database
            # parent, e.g. Redis: {Port: 6389, Endpoints: {Host: ...}}.
            # This is a verified config value, never a default guessed by LLM.
            local_ports = [
                safe_port(v) for k, v in node.items()
                if re.sub("[^a-z0-9]", "", str(k).lower()) == "port"
            ]
            explicit_port = next((p for p in local_ports if p is not None), inherited_port)
            for key, item in list(node.items())[:100]:
                name = re.sub("[^a-z0-9]", "", str(key).lower())
                if SECRET.search(name):
                    continue
                source_path = keypath + (str(key),)
                source_key = safe_config_key(source_path)
                next_hint = next((kind for part, (kind, _) in KINDS.items()
                                  if part in name), hint)
                if name in {"db", "dbserver", "dbsettings", "dbconfig"}:
                    next_hint = "database_tcp"
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
                        port = item.get("Port", item.get("port")) or explicit_port
                        if host and port:
                            put(next_hint or "custom_tcp", host, port, source_key=source_key)
                            # The same host key must not produce a spurious
                            # additional probe on the default vendor port.
                            reduced = {k: v for k, v in item.items()
                                       if k.lower() not in {"host", "hostname"}}
                            walk(reduced, next_hint, depth + 1, source_path, explicit_port)
                            continue
                    walk(item, next_hint, depth + 1, source_path, explicit_port)
                elif isinstance(item, list):
                    for child in item[:8]:
                        walk(child, next_hint, depth + 1, source_path, explicit_port)
                elif isinstance(item, str) and (
                    (next_hint and (next_hint != hint or name in ENDPOINT_FIELDS))
                    or (hint == "database" and (
                        "://" in item or item.lower().startswith(
                            ("server=", "host=", "data source=")
                        )
                    ))
                ):
                    parse(item, next_hint or "database", source_key, explicit_port)
        elif isinstance(node, str) and hint:
            parse(node, hint, safe_config_key(keypath), inherited_port)

    walk(config)
    return output
