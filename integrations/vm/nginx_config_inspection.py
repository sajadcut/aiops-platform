"""Bounded read-only Nginx file inventory and structural config inspection.

This diagnostic needs only /bin/sh, readlink, wc and awk on the VM. It never
prints directive values (upstreams, auth, cookies, URLs, certificates, tokens)
or reads arbitrary model/user-supplied paths. The caller supplies ONLY the
incident-bound service. An optional *error-file* location is derived by the
server from nginx's own syntax-validator output, not chat or an alarm.
"""
from __future__ import annotations

import re
import shlex

from integrations.vm.service_adapters import _absolute_config_path

_ROOTS = ("/etc/nginx/", "/usr/local/nginx/conf/")
_PATH = re.compile(r"^/(?:[A-Za-z0-9_.+-]+/)*[A-Za-z0-9_.+-]+$")
_ALLOWED_DIRECTIVES = frozenset((
    "user", "worker_processes", "worker_connections", "pid", "events",
    "http", "stream", "server", "location", "upstream", "map", "geo",
    "types", "include", "listen", "server_name", "root", "index",
    "try_files", "return", "rewrite", "proxy_pass", "proxy_set_header",
    "proxy_read_timeout", "proxy_connect_timeout", "proxy_send_timeout",
    "fastcgi_pass", "fastcgi_param", "access_log", "error_log",
    "ssl_certificate", "ssl_certificate_key", "ssl_protocols", "ssl_ciphers",
    "auth_basic", "auth_basic_user_file", "add_header", "limit_req_zone",
    "limit_req", "client_max_body_size", "resolver", "keepalive_timeout",
    "gzip", "set", "if", "allow", "deny", "default_type", "sendfile",
    "autoindex", "server_tokens", "proxy_redirect", "proxy_cache",
))
_STRUCTURAL = re.compile(r"^(?:[a-z_][a-z0-9_]{0,48}|brace_open|brace_close|unknown_directive)$")

# Shell output contains only the *directive name* (from a fixed allowlist) and
# numeric line index. Values are read by awk on the VM but never emitted.
_INSPECTION_SCRIPT = r'''
set -eu
if ! command -v readlink >/dev/null 2>&1 ||
   ! command -v awk >/dev/null 2>&1 ||
   ! command -v wc >/dev/null 2>&1; then
    printf 'ERROR\tcoreutils_or_awk_unavailable\n'
    exit 0
fi
focus=$1
focus_line=$2
total=0
# All input candidates below are literal system paths/globs except the first,
# which is an error path from the *trusted compiler output* (revalidated by
# the Python MCP adapter before it constructs this constant script).
for candidate in "$focus" \
    /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf \
    /etc/nginx/sites-enabled/* /etc/nginx/sites-available/*.conf \
    /usr/local/nginx/conf/nginx.conf /usr/local/nginx/conf/conf.d/*.conf
do
    [ "$total" -lt 24 ] || break
    [ -f "$candidate" ] || continue
    real=$(readlink -f -- "$candidate" 2>/dev/null) || continue
    case "$real" in
        /etc/nginx/*|/usr/local/nginx/conf/*) ;;
        *) continue ;;
    esac
    # Prevent newlines, shell control chars or strange paths in the line
    # protocol even if the target filesystem is adversarial.
    case "$candidate:$real" in
        *[!a-zA-Z0-9_./+:=-]* ) continue ;;
    esac
    [ -r "$real" ] || {
        printf 'UNREADABLE\t%s\n' "$candidate"
        continue
    }
    bytes=$(wc -c < "$real" 2>/dev/null) || continue
    case "$bytes" in *[!0-9]*|'') continue ;; esac
    if [ "$bytes" -gt 262144 ]; then
        printf 'SKIPPED\t%s\toversized\n' "$candidate"
        continue
    fi
    total=$((total+1))
    printf 'FILE\t%s\t%s\t%s\n' "$candidate" "$real" "$bytes"
    line=0
    if [ "$real" = "$focus" ]; then line=$focus_line; fi
    LC_ALL=C awk -v focus="$line" '
      BEGIN {
        split("user worker_processes worker_connections pid events http stream server location upstream map geo types include listen server_name root index try_files return rewrite proxy_pass proxy_set_header proxy_read_timeout proxy_connect_timeout proxy_send_timeout fastcgi_pass fastcgi_param access_log error_log ssl_certificate ssl_certificate_key ssl_protocols ssl_ciphers auth_basic auth_basic_user_file add_header limit_req_zone limit_req client_max_body_size resolver keepalive_timeout gzip set if allow deny default_type sendfile autoindex server_tokens proxy_redirect proxy_cache", names, " ")
        for(i in names) permitted[names[i]]=1
        ordinary=0
      }
      NR <= 25000 {
        text=$0
        sub(/^[ \t]+/, "", text)
        if(text == "" || substr(text,1,1)=="#") next
        token=text
        sub(/[ \t;{#].*$/, "", token)
        if(substr(text,1,1)=="}") token="brace_close"
        else if(substr(text,1,1)=="{") token="brace_open"
        else if(!(token in permitted)) token="unknown_directive"
        if(focus > 0 && NR >= focus-3 && NR <= focus+3)
           printf "ROW\t%d\t%s\n", NR, token
        else if(ordinary < 5) {
           printf "ROW\t%d\t%s\n", NR, token
           ordinary++
        }
      }
    ' "$real" 2>/dev/null || true
done
printf 'END\t%s\n' "$total"
'''


def nginx_inspection_command(failed_path: str | None, error_line: int | None) -> str:
    path = _absolute_config_path(failed_path) if failed_path else None
    if path and not path.startswith(_ROOTS):
        path = None
    if type(error_line) is not int or not 1 <= error_line <= 25000:
        error_line = 0
    # No LLM-controlled path or code: only compiler-derived, bounded filenames
    # and integer line numbers become arguments to the fixed shell script.
    return (
        "sh -c " + shlex.quote(_INSPECTION_SCRIPT) +
        " -- " + shlex.quote(path or "/__not_an_nginx_file__") +
        " " + shlex.quote(str(error_line))
    )


def parse_nginx_inspection(output: str) -> dict:
    """Allowlist protocol fields; no remote byte contents can cross the MCP."""
    files: list[dict] = []
    errors: list[str] = []
    current: dict | None = None
    completed = False
    for line in str(output or "")[:30000].splitlines()[:360]:
        fields = line.split("\t")
        if fields[0] == "FILE" and len(fields) == 4 and len(files) < 24:
            source, resolved, size = fields[1:]
            if not (_PATH.fullmatch(source) and _PATH.fullmatch(resolved)
                    and source.startswith(_ROOTS) and resolved.startswith(_ROOTS)
                    and size.isdecimal() and int(size) <= 262144):
                continue
            if any(f["source"] == source for f in files):
                current = None
                continue
            current = {"source": source, "resolved": resolved,
                       "size_bytes": int(size), "directives": []}
            files.append(current)
        elif fields[0] == "ROW" and len(fields) == 3 and current is not None:
            row, token = fields[1:]
            if (row.isdecimal() and 1 <= int(row) <= 25000
                    and token in _ALLOWED_DIRECTIVES | {"brace_open", "brace_close", "unknown_directive"}
                    and len(current["directives"]) < 13):
                current["directives"].append({"line": int(row), "directive": token})
        elif fields[0] in {"UNREADABLE", "SKIPPED"} and len(fields) >= 2:
            errors.append("file_read_restricted_or_skipped")
        elif fields[0] == "ERROR" and len(fields) == 2 and fields[1] == "coreutils_or_awk_unavailable":
            errors.append("coreutils_or_awk_unavailable")
        elif fields[0] == "END" and len(fields) == 2 and fields[1].isdecimal():
            completed = True
    return {
        "status": "inspected" if files and completed and not errors else
                  "partial" if files else "unavailable",
        "inspected_count": len(files),
        "files": files,
        "limitations": list(dict.fromkeys(errors))[:3],
        "includes_are_not_exhaustive": True,
        "line_values_exposed": False,
        "config_contents_exposed": False,
        "read_only": True,
        "validator_executed": False,
        "configuration_valid": None,
        "execution_authority": False,
    }
