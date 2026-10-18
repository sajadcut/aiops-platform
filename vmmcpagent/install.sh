#!/usr/bin/env bash
# Install a previously built vmmcpagent bundle. Run on an approved Linux VM
# as root. Does not install or enable the privileged sudoers policy.
set -euo pipefail
if [[ "${EUID}" -ne 0 ]]; then echo "Run as root" >&2; exit 1; fi
SRC="${1:-}"
if [[ -z "$SRC" || ! -f "$SRC/vmmcpagent" || ! -f "$SRC/agent.env.example" \
      || ! -f "$SRC/.env.example" || -L "$SRC/.env.example" ]]; then
  echo "Usage: sudo bash vmmcpagent/install.sh /path/to/dist/vmmcpagent" >&2
  exit 2
fi
# Do not accept a pre-populated secret from an install artifact.
if [[ -e "$SRC/agent.env" || -e "$SRC/.env" ]]; then
  echo "Build unexpectedly contains secrets; refusing install" >&2
  exit 3
fi
# Keep agent binaries/configuration and private runtime data below one root.
DST="/data/aiopsvmagent"
# The service user is selected from agent.env, not from credentials
# supplied over the network. Never execute sourced operator text as shell code.
# If the file is not installed yet, read the bundled template.
if [[ -L "$DST/agent.env" ]]; then
  echo "Refusing symlinked agent.env" >&2; exit 4
fi
ACTOR_CONFIG="$DST/agent.env"
if [[ ! -f "$ACTOR_CONFIG" ]]; then ACTOR_CONFIG="$SRC/agent.env.example"; fi
ACTOR="$(sed -n 's/^VM_AGENT_EXEC_USERNAME=//p' "$ACTOR_CONFIG" | tail -n 1)"
ACTOR="${ACTOR:-aiops-agent}"
if [[ ! "$ACTOR" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || [[ "$ACTOR" == root ]]; then
  echo "Invalid VM_AGENT_EXEC_USERNAME in agent.env" >&2; exit 4
fi
if ! id -u "$ACTOR" >/dev/null 2>&1; then
  echo "Create the configured VM_AGENT_EXEC_USERNAME account before installation" >&2
  exit 4
fi
ACTOR_GROUP="$(id -gn "$ACTOR")"
if [[ -L "$DST" || ( -e "$DST" && ! -d "$DST" ) ]]; then
  echo "Agent installation directory must be a real directory" >&2
  exit 5
fi
if [[ -e "$DST/agent.env" ]]; then
  echo "Existing $DST/agent.env will be preserved"
fi
install -d -o root -g root -m 0755 "$DST"
# install -d does not reliably repair an existing directory's mode.
# systemd runs the agent unprivileged and must be able to CHDIR here.
chmod 0755 "$DST"
cp -a "$SRC/." "$DST/"
# GNU cp -a SRC/. DST/ also copies the source DIRECTORY mode to DST,
# silently undoing the chmod above (PyInstaller build output can be 0700).
# Repair the destination *after* the archive copy. Otherwise the unprivileged
# systemd User cannot traverse WorkingDirectory and exits status=200/CHDIR.
# Secrets remain restricted individually (agent.env is mode 0600 below).
chmod 0755 "$DST"
# Preserve ownership and ciphertext contents of existing agent runtime data on
# upgrades. Only trusted package files are root-owned; data dirs are not.
chown root:root "$DST"
find "$DST" -mindepth 1 -maxdepth 1 \
  ! -name 'agent.env' ! -name 'config-candidates' ! -name 'logs' \
  -exec chown -R root:root -- {} +
# Candidate vault requires uid=aiops-agent and mode 0700 to pass its secure
# directory checks. The same private owner is used for on-host log files.
install -d -o "$ACTOR" -g "$ACTOR_GROUP" -m 0700 \
  "$DST/config-candidates" "$DST/logs"
# PyInstaller --onedir bundles its runtime under _internal. A build executed
# as root with umask 077 creates libpython*.so and its ancestor dirs as 0600/
# 0700; archive copying faithfully preserves those modes. systemd then exits
# status=255/EXCEPTION before the agent can load the Python runtime.
# Only the non-secret bundled runtime is made traversable/readable. Never
# recurse over DST itself: agent.env, logs and config-candidates stay private.
if [[ -L "$DST/_internal" || ! -d "$DST/_internal" ]]; then
  echo "Refusing missing or symlinked PyInstaller _internal directory" >&2
  exit 6
fi
chmod -R a+rX "$DST/_internal"
# .env.example is the checked-in NON-SECRET Pydantic default baseline.
# PyInstaller reads it at startup as the unprivileged systemd User, not root.
# cp -a preserves source modes (which may be 0600), so always normalize.
# Never do this to agent.env: that file contains live credentials.
if [[ -L "$DST/.env.example" || ! -f "$DST/.env.example" ]]; then
  echo "Refusing missing or symlinked non-secret .env.example" >&2; exit 6
fi
chown root:root "$DST/.env.example"
chmod 0644 "$DST/.env.example"
# Templates and binary may be world-readable; operator secrets may not.
chmod 0755 "$DST/vmmcpagent"
if [[ ! -f "$DST/agent.env" ]]; then
  install -o root -g root -m 0600 "$DST/agent.env.example" "$DST/agent.env"
else
  chmod 0600 "$DST/agent.env"
fi
# Provision per-host Ed25519 credentials automatically. Existing credentials
# are NEVER overwritten (avoid invalidating pending signed approvals).
# systemd LoadCredential exposes the private PEM only to the service, and the
# root-owned fixed guard reads only the matching public verification key.
install -d -o root -g root -m 0755 /etc/aiops
GUARD_PRIVATE=/etc/aiops/config-change-sign.pem
GUARD_PUBLIC=/etc/aiops/config-change-verify.pem
if [[ -L "$GUARD_PRIVATE" || -L "$GUARD_PUBLIC" ]]; then
  echo "Refusing symlinked Root Guard credentials" >&2; exit 7
fi
if [[ ! -e "$GUARD_PRIVATE" && ! -e "$GUARD_PUBLIC" ]]; then
  umask 077
  candidate="$(mktemp /etc/aiops/.guard-key.XXXXXXXX)"
  trap 'rm -f -- "$candidate"' EXIT
  openssl genpkey -algorithm Ed25519 -out "$candidate" >/dev/null
  chmod 0600 "$candidate"
  openssl pkey -in "$candidate" -pubout -out "$GUARD_PUBLIC"
  chown root:root "$GUARD_PUBLIC"
  chmod 0644 "$GUARD_PUBLIC"
  mv -n "$candidate" "$GUARD_PRIVATE"
  trap - EXIT
elif [[ ! -f "$GUARD_PRIVATE" || ! -f "$GUARD_PUBLIC" ]]; then
  echo "Incomplete existing Root Guard keypair; refusing automatic rotation" >&2
  exit 7
fi
if [[ ! -f "$GUARD_PRIVATE" || ! -f "$GUARD_PUBLIC" ]]; then
  echo "Root Guard keypair is incomplete" >&2; exit 7
fi
chown root:root "$GUARD_PRIVATE" "$GUARD_PUBLIC"
chmod 0600 "$GUARD_PRIVATE"
chmod 0644 "$GUARD_PUBLIC"
# Compare canonical public key derived from the private PEM, without printing
# any key material. Refuse mismatched or malformed keys rather than rotating.
derived="$(openssl pkey -in "$GUARD_PRIVATE" -pubout 2>/dev/null | openssl dgst -sha256)"
installed="$(openssl pkey -pubin -in "$GUARD_PUBLIC" -pubout 2>/dev/null | openssl dgst -sha256)"
if [[ -z "$derived" || "$derived" != "$installed" ]]; then
  echo "Root Guard signing and verification keys do not match" >&2; exit 7
fi
install -o root -g root -m 0750 "$DST/aiops-config-guard" /usr/local/sbin/aiops-config-guard
install -o root -g root -m 0644 "$DST/vmmcpagent.service" /etc/systemd/system/vmmcpagent.service
# systemd cannot expand User= from EnvironmentFile; install a root-owned
# drop-in for the exact locally configured user instead.
install -d -o root -g root -m 0755 /etc/systemd/system/vmmcpagent.service.d
printf '[Service]\nUser=%s\nGroup=%s\n' "$ACTOR" "$ACTOR_GROUP" \
  > /etc/systemd/system/vmmcpagent.service.d/10-execution-user.conf
chmod 0644 /etc/systemd/system/vmmcpagent.service.d/10-execution-user.conf
systemctl daemon-reload
echo "Installed. Edit $DST/agent.env and configure:"
echo " - VM_AGENT_TARGET, VM_AGENT_ALLOWED_SERVICES, VM_AGENT_BEARER_TOKEN"
echo " - Root Guard signing credentials are provisioned automatically and preserved on upgrades"
echo " - restricted sudoers and TLS reverse proxy. Service NOT automatically enabled."
