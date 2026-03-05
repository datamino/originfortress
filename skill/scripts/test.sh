#!/usr/bin/env bash
# Origin Fortress test wrapper — runs detection test suite
set -euo pipefail

if [ -n "${ORIGIN_FORTRESS_BIN:-}" ]; then
  ORIGIN_FORTRESS="$ORIGIN_FORTRESS_BIN"
elif command -v origin-fortress &>/dev/null; then
  ORIGIN_FORTRESS="origin-fortress"
else
  SCRIPT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
  ORIGIN_FORTRESS="node $SCRIPT_DIR/bin/origin-fortress.js"
fi
exec $ORIGIN_FORTRESS test
