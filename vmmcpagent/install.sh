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
DST="/opt/vmmcpagent"
if [[ -e "$DST/agent.env" ]]; then
  echo "Existing $DST/agent.env will be preserved"
fi
install -d -o root -g root -m 0755 "$DST"
cp -a "$SRC/." "$DST/"
chown -R root:root "$DST"
# Templates and binary may be world-readable; operator secrets may not.
chmod 0755 "$DST/vmmcpagent"
if [[ ! -f "$DST/agent.env" ]]; then
  install -o root -g root -m 0600 "$DST/agent.env.example" "$DST/agent.env"
else
  chmod 0600 "$DST/agent.env"
fi
install -o root -g root -m 0750 "$DST/aiops-config-guard" /usr/local/sbin/aiops-config-guard
install -o root -g root -m 0644 "$DST/vmmcpagent.service" /etc/systemd/system/vmmcpagent.service
systemctl daemon-reload
echo "Installed. Edit /opt/vmmcpagent/agent.env and configure:"
echo " - VM_AGENT_TARGET, VM_AGENT_ALLOWED_SERVICES, VM_AGENT_BEARER_TOKEN"
echo " - root-owned /etc/aiops/config-change-verify.pem and host-specific signing seed for APPLY"
echo " - restricted sudoers and TLS reverse proxy. Service NOT automatically enabled."
