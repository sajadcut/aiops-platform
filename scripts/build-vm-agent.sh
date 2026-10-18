#!/usr/bin/env bash
# Backwards-compatible command: build all vmmcpagent assets in their own folder.
set -euo pipefail
cd "$(dirname "$0")/.."
exec bash vmmcpagent/build.sh "$@"
