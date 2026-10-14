"""Bounded Nginx syntax repair *preview*; never writes production configuration.

A narrow, deterministic candidate is permitted only for an extraneous brace
on the exact fatal line. The candidate is tested against a staging copy using
nginx -t (which can still load the original includes). Because staging is NOT
isolated, the result is never eligible for automatic approval or deployment.
No source configuration values, passwords, or raw validator stdout are exported.
"""
from __future__ import annotations

import re
import shlex

from integrations.vm.service_adapters import _absolute_config_path

_ALLOWED_ROOTS = ("/etc/nginx/", "/usr/local/nginx/conf/")
_FIXED_CHECK = r'''
import hashlib, json, os, re, stat, subprocess, tempfile, sys
file_path, error_number, error_kind = sys.argv[1:]
result = {
 "status": "unavailable", "validation_status": "UNVERIFIED",
 "validator_executed_on_proposal": False, "current_hash": None,
 "candidate_hash": None, "file": file_path, "error_line": int(error_number),
 "current_excerpt": [], "proposed_excerpt": [], "diff": None,
 "proposed_change": None, "test_scope": "not_tested",
 "stage_failure_reason": "not_tested",
 "execution_authority": False, "config_contents_exposed": False,
}
def stage_failure_class(stderr):
    # Only return fixed categories; never return raw stderr, file contents,
    # directive arguments, upstream names, credentials or include paths.
    info = stderr.decode("utf-8", "replace")[:4096].lower()
    if 'unexpected "{"' in info or "unexpected '{'" in info:
        return "unexpected_open_brace_still_present"
    if 'unexpected "}"' in info or "unexpected '}'" in info:
        return "unexpected_closing_brace"
    if "directive is not allowed here" in info or "is not allowed here" in info:
        return "directive_context_invalid"
    if "invalid number of arguments" in info:
        return "directive_arguments_invalid"
    if "host not found in upstream" in info:
        return "upstream_resolution_failed"
    if "permission denied" in info:
        return "permission_denied"
    if "no such file or directory" in info:
        return "referenced_file_missing"
    return "nginx_staged_check_failed_unspecified"

def visible_line(value):
    stripped = value.strip()
    if not stripped or stripped.startswith("#"):
        return "[blank or comment]"
    # Only a structural directive name and braces; NEVER directive arguments.
    m = re.match(r"([a-zA-Z_][a-zA-Z0-9_]*)", stripped)
    name = m.group(1)[:40] if m else "[structural]"
    braces = "".join(ch for ch in stripped if ch in "{}")[:8]
    return name + (" [arguments redacted]" if m else "") + (" " + braces if braces else "")
try:
    if not (file_path.startswith("/etc/nginx/") or file_path.startswith("/usr/local/nginx/conf/")):
        raise ValueError("path_outside_nginx_roots")
    if os.path.normpath(file_path) != file_path or os.path.realpath(file_path) != file_path:
        raise ValueError("unsafe_path")
    folder, name = os.path.split(file_path)
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in filter(None, folder.split("/")):
            nxt = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            os.close(directory)
            directory = nxt
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            st = os.fstat(fd)
            if not stat.S_ISREG(st.st_mode) or st.st_size > 262144:
                raise ValueError("not_regular_or_too_large")
            with os.fdopen(fd, "rb") as inp:
                fd = -1
                original = inp.read(262145)
            if len(original) > 262144:
                raise ValueError("too_large")
        finally:
            if fd >= 0: os.close(fd)
    finally:
        os.close(directory)
    raw_text = original.decode("utf-8")
    if "\r" in raw_text or "\x00" in raw_text:
        raise ValueError("unsupported_config_encoding")
    lines = raw_text.splitlines(keepends=True)
    line_no = int(error_number)
    if not 1 <= line_no <= len(lines):
        raise ValueError("error_line_out_of_bounds")
    result["current_hash"] = hashlib.sha256(original).hexdigest()
    start, end = max(0, line_no-4), min(len(lines), line_no+3)
    result["current_excerpt"] = [
      {"line":i+1, "content":visible_line(lines[i])}
      for i in range(start,end)
    ]
    result["status"] = "observed"
    line = lines[line_no-1]
    replacement = None
    if error_kind == "unexpected_open_brace":
        if line.strip() == "{":
            replacement = ""
        else:
            # Restricted, obvious duplicated opening brace in standard block
            # declarations; never execute or forward arbitrary model patches.
            m = re.fullmatch(
              r"(\s*(?:server|http|events|stream|upstream|location|map|types)"
              r"(?:\s+[^{}#\r\n]+)?\s*\{)\s*\{\s*\n?", line
            )
            if m:
                replacement = m.group(1) + ("\n" if line.endswith("\n") else "")
    if replacement is not None:
        proposed_lines = list(lines)
        proposed_lines[line_no-1] = replacement
        candidate = "".join(proposed_lines).encode("utf-8")
        result["candidate_hash"] = hashlib.sha256(candidate).hexdigest()
        result["proposed_excerpt"] = [
          {"line":i+1,"content":visible_line(proposed_lines[i])}
          for i in range(start,end)
        ]
        result["diff"] = {
          "line":line_no,
          "before": visible_line(line),
          "after": visible_line(replacement) if replacement else "[remove entire stray brace line]",
          "redacted": True,
        }
        result["proposed_change"] = "remove_extra_opening_brace"
        result["status"] = "candidate_proposed"
        # Test a temporary staging copy, not the running configuration.
        # This is NOT a sandbox: installed Nginx includes/dependencies are live.
        binaries = [x for x in ("/usr/sbin/nginx", "/usr/local/nginx/sbin/nginx")
                    if os.path.isfile(x) and os.access(x, os.X_OK)]
        if binaries:
            with tempfile.TemporaryDirectory(prefix="aiops-nginx-review-") as temp:
                candidate_path = os.path.join(temp, "nginx.conf")
                with open(candidate_path, "xb") as out:
                    out.write(candidate)
                try:
                    check = subprocess.run(
                       [binaries[0], "-t", "-c", candidate_path,
                        "-p", "/etc/nginx/" if file_path.startswith("/etc/nginx/") else "/usr/local/nginx/"],
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.PIPE, timeout=8, check=False,
                       env={"PATH":"/usr/sbin:/usr/bin:/bin","LC_ALL":"C"}
                    )
                    result["validator_executed_on_proposal"] = True
                    result["test_scope"] = "staged_copy_with_live_dependencies_not_isolated"
                    result["validation_status"] = (
                      "STAGED_PASS_NOT_ISOLATED" if check.returncode == 0
                      else "STAGED_FAILED"
                    )
                    result["stage_failure_reason"] = (
                      "none" if check.returncode == 0
                      else stage_failure_class(check.stderr or b"")
                    )
                except subprocess.TimeoutExpired:
                    result["validation_status"] = "UNVERIFIED"
                    result["stage_failure_reason"] = "stage_timeout"
                except OSError:
                    result["validation_status"] = "UNVERIFIED"
                    result["stage_failure_reason"] = "nginx_staging_unavailable"
        else:
            result["validation_status"] = "UNVERIFIED"
            result["stage_failure_reason"] = "nginx_binary_not_found"
except (OSError, UnicodeError, ValueError):
    result["status"] = "unavailable"
print(json.dumps(result, separators=(",",":")))
'''


def nginx_review_command(path: str, line: int, syntax_error: str) -> str:
    """The inputs originate exclusively from a verified, failed VM validator."""
    safe = _absolute_config_path(path)
    if not safe or not safe.startswith(_ALLOWED_ROOTS):
        raise ValueError("nginx_config_path_not_allowed")
    if type(line) is not int or not 1 <= line <= 100000:
        raise ValueError("nginx_error_line_not_valid")
    failure = str(syntax_error or "")
    kind = "unexpected_open_brace" if re.search(r'unexpected\s+["\u201c]?\{', failure, re.I) else "other"
    return "python3 -I -c " + shlex.quote(_FIXED_CHECK) + " " + " ".join(
        shlex.quote(str(v)) for v in (safe, line, kind)
    )
