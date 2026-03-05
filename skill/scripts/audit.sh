#!/usr/bin/env bash
# Origin Fortress audit wrapper — audits session logs
set -euo pipefail

LOGFILE="${ORIGIN_FORTRESS_LOG:-origin-fortress-scan.log}"
if [ -n "${ORIGIN_FORTRESS_BIN:-}" ]; then
  ORIGIN_FORTRESS="$ORIGIN_FORTRESS_BIN"
elif command -v origin-fortress &>/dev/null; then
  ORIGIN_FORTRESS="origin-fortress"
else
  SCRIPT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
  ORIGIN_FORTRESS="node $SCRIPT_DIR/bin/origin-fortress.js"
fi
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SESSION_DIR="${1:-$HOME/.openclaw/agents/main/sessions/}"

OUTPUT=$($ORIGIN_FORTRESS audit "$SESSION_DIR" 2>&1) || true

echo "[$TIMESTAMP] audit $SESSION_DIR" >> "$LOGFILE"
echo "$OUTPUT" >> "$LOGFILE"
echo "---" >> "$LOGFILE"

echo "$OUTPUT"

if echo "$OUTPUT" | grep -qiE '(CRITICAL|HIGH|FAIL)'; then
  echo "⚠️  Security issues found in audit!" >&2
  exit 1
fi
