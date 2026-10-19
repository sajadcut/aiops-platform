# Universal dependency investigation

## Principle
Identify the actual application bound to an Incident before examining downstream dependencies. Use an alert and bounded logs to prioritize a configuration inspection, not to invent a host, execute an LLM-generated command, or authorize recovery.

## Evidence-first workflow
1. Correlate alert to a known service and allowed VM target.
2. Classify database, message broker, cache or HTTP dependency errors from recorded alerts/logs.
3. Discover valid candidate paths from systemd ExecStart, WorkingDirectory, and publish root.
4. Verify canonical readable non-symlink service config files before reading.
5. Decode JSON/JSONC, YAML, Properties/INI, Tomcat XML or .NET app.config only inside trusted VM MCP worker.
6. Extract static dependency host/port/protocol metadata without passwords, URL path/query, or raw configuration contents.
7. Execute at most six read-only probes: TCP for databases, brokers, caches and unknown custom host-port endpoints; HTTP HEAD on root without credentials, redirects, proxy, or body for configured HTTP(S) URLs.
8. Store sanitized MCP evidence and show checks, results, and references in Incident Room. The LLM must identify remaining uncertainty.

## Supported categories

- SQL and data stores: PostgreSQL, MySQL, MariaDB, SQL Server, MongoDB, Cassandra, Neo4j
- Brokers: ActiveMQ/Artemis, RabbitMQ/AMQP, Kafka, MQTT, NATS and ZooKeeper
- Cache and search: Redis, Memcached, OpenSearch, Elasticsearch
- HTTP and HTTPS APIs: declared outbound URLs, SOAP/REST services, and upstreams
- Unrecognized technologies: explicit canonical host and port only; label custom_tcp, never infer a vendor.

Connection to a TCP port proves neither protocol-level health nor authentication. HTTP 401, 404 or 503 proves receipt of a response, not application readiness. All dependency diagnosis remains advisory and read-only. Application health, root cause and recovery remain unverified without stronger independent evidence.

## Safety limits

- No LLM-driven arbitrary shell, unverified filename or network address.
- No Python installation on the monitored machine.
- Config reads are bounded by existing worker path, 256 KiB, canonicalization and symlink checks; at most four files and six probes.
- Never persist a password, full connection string, HTTP query, config body or secret-backed environment variable.
- Only supports allowed Linux/systemd VMs in this iteration. Windows SCM, Kubernetes-native workloads, encrypted configs, secrets supplied exclusively by environment, SQL/AMQP authentication, Redis PING, TLS mutual auth, distributed tracing and true application endpoint semantics need separate safe adapters.
- No Write/Approval rules or human authorization gates have been relaxed.

## Real environment requirement
REAL ENV REQUIRED: stage with an allowlisted service using a configured database, broker and HTTP API. Verify path discovery, tool calls, network policy, timeouts, no secret leakage, and meaningful Incident Room reports. Green CI is not proof of production readiness.
