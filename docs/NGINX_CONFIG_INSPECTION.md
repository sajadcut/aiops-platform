# Incident Chat: bounded read-only Nginx configuration file inspection

## Why this is needed

The old Incident Chat sometimes responded that it had no access to `nginx.conf`
or `sites-enabled`, despite the Incident's VM MCP already being able to run
`nginx -t`. The previous `nginx_config_review` capability only previews one
compiler-confirmed failure, and does not list the Nginx configuration tree.
The former review-preview feature depended on target-side Python 3; both the current structural inspection and the revised worker-side repair preview now avoid that dependency.

## New MCP capability: `nginx_config_inspect`

**Inputs:** `target` and `service` only. It is available only for a
corroborated, allowlisted **nginx** service, through the existing VM MCP
authorization and remote SSH policy. The incident-copilot binds the host
from persisted `service_status` evidence, not from model text.

The connector first executes the existing `config_validate` (`nginx -t`)
and extracts the compiler's actual error file and line when available. It
then runs an immutable, read-only `/bin/sh` inspection program. The program
enumerates only installed Nginx config roots under `/etc/nginx` and
`/usr/local/nginx/conf`, including `nginx.conf`, `conf.d/*.conf`,
`sites-enabled/*`, and `sites-available/*.conf`. It allows symlinks only
when their real destination remains inside one of these roots. It processes
a maximum of 24 files at up to 256 KiB each and reports at most 13 directive
names/line positions per file. These bounds mean included files are **not
guaranteed exhaustive**.

**Never exported:** complete file contents, directive arguments, passwords,
URLs, upstream hosts, headers, certificate bytes or token values. Unknown
directive names are replaced by `unknown_directive`. The result is
**structure and line numbers**, not a full file editor or config diff.

The VM needs only `sh`, `readlink`, `wc` and `awk`; no Python, jq,
.NET SDK or container is installed or required on the investigated server.
The MCP result includes the separate `nginx -t` validation status. Seeing a
file is not a proof of its syntax validity, and an unavailable validator is
never interpreted as valid.

## Using it from the Incident Room

Open an analyzed Nginx incident and choose **Inspect Nginx files** or type
`فایل nginx.conf و sites-enabled را بررسی کن`. The API chooses the registered
read-only tool, performs the VM MCP read and gives the LLM the sanitized
observation. The chat answer always includes the factual file/line inventory
from the MCP, regardless of a vague or incorrect model narrative. The
assistant MUST NOT say it has no file access when the check succeeded.
If it fails, the answer reports the actual unavailable status alongside
previously stored incident evidence.

The same fixed capability is also allowed in the opt-in dynamic agent
investigation planner for failed Nginx configuration validation.

## Deployment and real permissions

Deploy the updated AIOps API, VM MCP service and Incident Room dashboard
together. The existing Incident Chat route and read:incident authorization
remain in force. No sudo permission is added for arbitrary config reads.
The VM MCP SSH identity must have OS read permission on the relevant
Nginx configs and directories. **A source-code change cannot grant Linux
filesystem permissions on the target server.** Grant narrowly scoped read
rights through the infrastructure team's approved ACL/group policy when
needed; never make private keys, auth secrets, or all of `/etc` readable.

The VM MCP endpoint must remain configured and reachable. Tested by CI with
controlled remote-shell fixtures; real VM read permissions and the concrete
Nginx installation are **REAL ENV REQUIRED**.

This capability is always read-only: no `chmod`, `sudo`, `nginx -s reload`,
`systemctl` writes, ad hoc command execution or production patch Apply.
Actual remediation still requires the preexisting guarded approval workflow.
