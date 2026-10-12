# Elastic MCP connectivity diagnostic

Run this read-only diagnostic inside the same AIOps environment/container
that reported Elastic Agent Builder MCP HTTP 401. It uses the project's actual
ElasticsearchMCPClient and its configured Basic/API-key Authorization value,
not an independently supplied username and password.

From the repository root:

~~~bash
python -m scripts.check_elastic_mcp
~~~

For Docker Compose, if the Python code and the scripts package are present
in the image for your API service:

~~~bash
docker compose exec <api-service-name> python -m scripts.check_elastic_mcp
~~~

The script calls MCP initialize, sends the standard initialized notification
through the existing client, and checks tools/list for the allowlisted
platform.core.execute_esql tool. It does not execute ES|QL queries,
mutate data, or print the Authorization header, password, URL userinfo, or
server response body. It prints the effective authentication scheme and whether
credential environment variables override local config files.

| Exit code | Meaning |
|---|---|
| 0 | MCP initialization and required tool discovery succeeded |
| 2 | No effective Authorization header, or client configuration failed |
| 3 | HTTP 401; verify effective runtime credentials/authentication |
| 4 | HTTP 403; check Agent Builder Read, Kibana Space and access policies |
| 5 | Other HTTP/transport/protocol failure |
| 6 | Connection succeeded, but required ES|QL MCP tool is unavailable |

A login in the Kibana browser is not proof that the HTTP Basic/MCP route
will accept the same credentials. If direct curl -u returns HTTP 403 while
the script returns HTTP 401, compare actual runtime environment overrides,
container configuration, authentication method and network/proxy routing.
Do not grant superuser to work around an authorization problem.

Production credentials require TLS with verified certificates. This diagnostic
uses the same transport policy as the existing AIOps MCP client; using this
diagnostic successfully is not proof of end-to-end production readiness.
