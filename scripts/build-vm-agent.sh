#!/usr/bin/env bash
# Build a Python-runtime-bundled Linux VM agent on a compatible Linux builder.
# The destination host does not need a separate Python installation.
# Requires project dependencies and PyInstaller in the BUILDER venv.
set -euo pipefail
cd "$(dirname "$0")/.."
command -v pyinstaller >/dev/null 2>&1 || {
  echo 'PyInstaller is required on the build host' >&2; exit 1;
}
# Never include populated .env or local secrets in the bundle.
pyinstaller --clean --noconfirm --onedir \
  --name aiops-vm-agent \
  --paths . \
  --collect-submodules apps \
  --collect-submodules integrations \
  --collect-submodules domain \
  --collect-submodules agents \
  --collect-data certifi \
  --add-data '.env.example:.' \
  apps/vm_agent_runner.py
# Settings reads .env.example relative to systemd WorkingDirectory. Package
# a non-secret template OUTSIDE PyInstaller's _internal dir for frozen runs.
cp .env.example dist/aiops-vm-agent/.env.example
# Privileged host helper is provisioned separately by a trusted root admin.
# Bundle its source for review/installation, never auto-install as root.
cp scripts/vm/aiops-config-guard dist/aiops-vm-agent/aiops-config-guard
echo "Bundle: dist/aiops-vm-agent/ (must undergo Linux runtime acceptance)"
