#!/usr/bin/env bash
# Build the installable vmmcpagent bundle on a compatible Linux builder.
# Python/PyInstaller are required ONLY on the builder, not on target VMs.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
command -v pyinstaller >/dev/null 2>&1 || {
  echo "PyInstaller is required on the Linux build machine" >&2; exit 1;
}
test -f .env.example
test -f vmmcpagent/agent.env.example
# Secrets must never be added as PyInstaller data or copied into the artifact.
pyinstaller --clean --noconfirm --onedir --name vmmcpagent \
  --paths "$ROOT" \
  --collect-submodules apps \
  --collect-submodules integrations \
  --collect-submodules domain \
  --collect-submodules agents \
  --collect-submodules vmmcpagent \
  --collect-data certifi \
  --add-data '.env.example:.' \
  vmmcpagent/__main__.py
BUNDLE="$ROOT/dist/vmmcpagent"
# BaseSettings expects a complete non-secret configuration baseline.
cp "$ROOT/.env.example" "$BUNDLE/.env.example"
# Non-secret baseline must be readable by the unprivileged installed systemd user.
chmod 0644 "$BUNDLE/.env.example"
cp "$ROOT/vmmcpagent/agent.env.example" "$BUNDLE/agent.env.example"
cp "$ROOT/vmmcpagent/vmmcpagent.service" "$BUNDLE/vmmcpagent.service"
cp "$ROOT/vmmcpagent/sudoers.example" "$BUNDLE/sudoers.example"
cp "$ROOT/vmmcpagent/aiops-config-guard" "$BUNDLE/aiops-config-guard"
cp "$ROOT/vmmcpagent/README.md" "$BUNDLE/README.md"
# An operator must provide agent.env explicitly after installation.
test ! -e "$BUNDLE/agent.env"
echo "Ready: $BUNDLE"
