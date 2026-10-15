"""Trusted *ephemeral* POSIX config transaction, delivered via SSH stdin.

No agent or helper needs installation on the monitored Linux VM. The control
plane verifies signed, one-use human approval before an apply request reaches
this builder. This fixed script cannot be supplied or modified by the LLM.
It never receives secrets or config contents as remote command arguments.

Security boundary: using sudo /bin/sh requires that the existing SSH identity
is already approved for privileged scripting (as with sudo su). Hosts which
only permit the old narrow aiops-config-guard sudoers entry fail closed until
their authorized privilege policy is changed by a human.
"""
from __future__ import annotations

import base64
import re
import shlex

_MAX_CONFIG_BYTES = 262144
_SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_PROFILE = {"nginx", "json_syntax", "xml_syntax"}

# This program is NEVER placed in a persistent executable on a target.
# stdin transports this fixed, locally maintained source and a base64
# representation of the candidate. The base64 heredoc cannot inject shell.
_SHELL = r'''#!/bin/sh
set -eu
umask 077
action=$1
profile=$2
file=$3
expected_source=$4
expected_candidate=$5

[ "$(id -u)" -eq 0 ] || exit 41
case "$action" in validate|apply) ;; *) exit 41 ;; esac
case "$profile:$file" in
  nginx:/etc/nginx/*.conf) ;;
  json_syntax:/etc/*.json|json_syntax:/opt/*.json|json_syntax:/srv/*.json|json_syntax:/data/*.json|json_syntax:/usr/local/etc/*.json|json_syntax:/usr/local/tomcat/*.json) ;;
  xml_syntax:/etc/*.xml|xml_syntax:/opt/*.xml|xml_syntax:/srv/*.xml|xml_syntax:/data/*.xml|xml_syntax:/usr/local/etc/*.xml|xml_syntax:/usr/local/tomcat/*.xml) ;;
  *) exit 41 ;;
esac
case "$file" in
  /etc/shadow|/etc/ssh/*|/etc/ssl/*|/etc/pki/*|/etc/security/*|/opt/secrets/*|/run/*|/proc/*|/sys/*|/dev/*) exit 41 ;;
  *secret*|*password*|*credential*|*private*|*.key) exit 41 ;;
  *"/../"*|*"/./"*|*" "*|*"	"*|*"
"*) exit 41 ;;
esac
for hash in "$expected_source" "$expected_candidate"; do
  case "$hash" in *[!0123456789abcdef]*|"") exit 41 ;; esac
  [ "$(printf '%s' "$hash" | wc -c)" -eq 64 ] || exit 41
done
[ -f "$file" ] && [ ! -L "$file" ] && [ "$(readlink -f -- "$file")" = "$file" ] || exit 42
command -v sha256sum >/dev/null && command -v flock >/dev/null &&
  command -v mktemp >/dev/null && command -v base64 >/dev/null || exit 42
[ "$(stat -c %s -- "$file")" -le 262144 ] || exit 42
if [ "$profile" = nginx ]; then
  [ -x /usr/sbin/nginx ] && command -v unshare >/dev/null &&
    command -v mount >/dev/null || exit 42
  [ "$(du -sk /etc/nginx | cut -f1)" -le 51200 ] || exit 42
elif [ "$profile" = json_syntax ]; then
  command -v jq >/dev/null || exit 42
else
  command -v xmllint >/dev/null || exit 42
fi

stage=$(mktemp -d /var/tmp/aiops-config-stage.XXXXXXXX) || exit 42
chmod 700 "$stage"
new=""
cleanup() {
  [ -z "$new" ] || rm -f -- "$new"
  rm -rf -- "$stage"
}
trap cleanup EXIT HUP INT TERM
# Candidate is base64-encoded before being inserted in this single-quoted
# heredoc by a trusted builder. Never interpolate plaintext into POSIX shell.
base64 -d > "$stage/candidate" <<'__AIOPS_CONFIG_CANDIDATE_B64__'
__CANDIDATE_BASE64__
__AIOPS_CONFIG_CANDIDATE_B64__
[ "$(stat -c %s "$stage/candidate")" -le 262144 ] || exit 42
[ "$(sha256sum "$stage/candidate" | cut -d ' ' -f1)" = "$expected_candidate" ] || exit 43

if [ "$action" = apply ]; then
  exec 9>/run/lock/aiops-config-transaction.lock
  flock -x -w 15 9 || exit 44
fi
[ "$(sha256sum "$file" | cut -d ' ' -f1)" = "$expected_source" ] || exit 45

if [ "$profile" = nginx ]; then
  cp -a -- /etc/nginx "$stage/tree" || exit 46
  relative=$(printf '%s' "$file" | sed 's@^/etc/nginx/@@')
  [ -f "$stage/tree/$relative" ] && [ ! -L "$stage/tree/$relative" ] || exit 46
  cp -- "$stage/candidate" "$stage/tree/$relative" || exit 46
  # The live tree is never written during validation. Mount isolation is
  # mandatory: nginx -t -c on a bare staged config is NOT an equivalent test.
  unshare -m --propagation private -- /bin/true >/dev/null 2>&1 || exit 50
  set +e
  unshare -m --propagation private -- /bin/sh -c '
    set -eu
    mount --bind "$1" /etc/nginx >/dev/null 2>&1 || exit 51
    mount -o remount,bind,ro /etc/nginx >/dev/null 2>&1 || exit 51
    /usr/sbin/nginx -t -c "$2" >/dev/null 2>&1 || exit 47
  ' aiops-guard "$stage/tree" "$file" >/dev/null 2>&1
  validation_rc=$?
  set -e
  [ "$validation_rc" -eq 0 ] || exit "$validation_rc"
elif [ "$profile" = json_syntax ]; then
  jq empty "$stage/candidate" >/dev/null 2>&1 || exit 47
else
  ! grep -Eiq '<!(DOCTYPE|ENTITY)' "$stage/candidate" || exit 47
  xmllint --nonet --noout "$stage/candidate" >/dev/null 2>&1 || exit 47
fi

if [ "$action" = validate ]; then
  printf 'VALIDATED\n'
  exit 0
fi

# No apply entrypoint is reachable without a control-plane validated,
# short-lived signed claim and consumed DB approval. Defense in depth on
# the host: exact candidate/source hash, lock, backup, postcheck, rollback.
[ "$(sha256sum "$file" | cut -d ' ' -f1)" = "$expected_source" ] || exit 45
backup_dir=/var/lib/aiops/config-backups
mkdir -p -m 0700 -- "$backup_dir"
chmod 0700 "$backup_dir"
backup=$(mktemp "$backup_dir/backup.XXXXXXXX") || exit 46
cp -a -- "$file" "$backup" || exit 46
new=$(mktemp "$(dirname "$file")/.aiops-config.XXXXXXXX") || exit 46
cp -a -- "$file" "$new" || exit 46
cat "$stage/candidate" > "$new" || exit 46
[ "$(sha256sum "$new" | cut -d ' ' -f1)" = "$expected_candidate" ] || exit 43
[ "$(sha256sum "$file" | cut -d ' ' -f1)" = "$expected_source" ] || exit 45
mv -f -- "$new" "$file" || exit 46
new=""

postcheck="failed"
if [ "$profile" = nginx ]; then
  if /usr/sbin/nginx -t -c "$file" >/dev/null 2>&1; then postcheck="passed"; fi
elif [ "$profile" = json_syntax ]; then
  if jq empty "$file" >/dev/null 2>&1; then postcheck="passed"; fi
else
  if ! grep -Eiq '<!(DOCTYPE|ENTITY)' "$file" &&
     xmllint --nonet --noout "$file" >/dev/null 2>&1; then
    postcheck="passed"
  fi
fi
if [ "$postcheck" = passed ] &&
   [ "$(sha256sum "$file" | cut -d ' ' -f1)" = "$expected_candidate" ]; then
  printf 'APPLIED_VERIFIED\n'
  exit 0
fi
new=$(mktemp "$(dirname "$file")/.aiops-rollback.XXXXXXXX") || exit 49
cp -a -- "$backup" "$new" || exit 49
mv -f -- "$new" "$file" || exit 49
new=""
if [ "$(sha256sum "$file" | cut -d ' ' -f1)" = "$expected_source" ]; then
  printf 'ROLLED_BACK\n'
  exit 48
fi
printf 'ROLLBACK_FAILED\n'
exit 49
'''


def build_ephemeral_guard(*, action: str, profile: str, path: str,
                          original_sha256: str, candidate_sha256: str,
                          candidate: str) -> tuple[str, str]:
    """Return (fixed sudo command, shell stdin); only allow predetermined operations."""
    if action not in {"validate", "apply"} or profile not in _PROFILE:
        raise ValueError("unregistered_config_repair_profile")
    if not (isinstance(path, str) and path.startswith("/") and
            not any(x in path for x in ("\n", "\r", "\x00", "\t", " ", "'", '"')) and
            isinstance(candidate, str)):
        raise ValueError("unsafe_ephemeral_config_contract")
    if not all(isinstance(h, str) and _SHA256.fullmatch(h)
               for h in (original_sha256, candidate_sha256)):
        raise ValueError("unsafe_ephemeral_config_hash")
    payload = candidate.encode("utf-8")
    if not 0 < len(payload) <= _MAX_CONFIG_BYTES:
        raise ValueError("invalid_ephemeral_candidate_size")
    encoded = base64.b64encode(payload).decode("ascii")
    # The encoded candidate contains only RFC4648 symbols; it cannot end
    # the heredoc or introduce shell statements.
    script = _SHELL.replace("__CANDIDATE_BASE64__", encoded)
    args = (action, profile, path, original_sha256, candidate_sha256)
    command = "/bin/sh -s -- " + " ".join(shlex.quote(x) for x in args)
    return command, script
