#!/usr/bin/env bash
# Install a previously built vmmcpagent bundle. Run on an approved Linux VM
# as root. Does not install or enable the privileged sudoers policy.
set -euo pipefail
if [[ "${EUID}" -ne 0 ]]; then echo "Run as root" >&2; exit 1; fi
SRC="${1:-}"
if [[ -z "$SRC" || ! -f "$SRC/vmmcpagent" || ! -f "$SRC/agent.env.example" ]]; then
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
cp -a "$SRC/." "$DST/"
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
# Templates and binary may be world-readable; operator secrets may not.
chmod 0755 "$DST/vmmcpagent"
if [[ ! -f "$DST/agent.env" ]]; then
  install -o root -g root -m 0600 "$DST/agent.env.example" "$DST/agent.env"
else
  chmod 0600 "$DST/agent.env"
fi
install -o root -g root -m 0750 "$DST/aiops-config-guard" /usr/local/sbin/aiops-config-guard
install -o root -g root -m 0644 "$DST/vmmcpagent.service" /etc/systemd/system/vmmcpagent.service
# systemd cannot expand User= from EnvironmentFile; install a root-owned
# drop-in for the exact locally configured user instead.
install -d -o root -g root -m 0755 /etc/systemd/system/vmmcpagent.service.d
printf '[Service]\\nUser=%s\\nGroup=%s\\n' "$ACTOR" "$ACTOR_GROUP" \
  > /etc/systemd/system/vmmcpagent.service.d/10-execution-user.conf
chmod 0644 /etc/systemd/system/vmmcpagent.service.d/10-execution-user.conf
systemctl daemon-reload
echo "Installed. Edit $DST/agent.env and configure:"
echo " - VM_AGENT_TARGET, VM_AGENT_ALLOWED_SERVICES, VM_AGENT_BEARER_TOKEN"
echo " - root-owned /etc/aiops/config-change-verify.pem and host-specific signing seed for APPLY"
echo " - restricted sudoers and TLS reverse proxy. Service NOT automatically enabled."
