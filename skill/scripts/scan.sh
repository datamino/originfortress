#!/usr/bin/env bash
# Origin Fortress scan wrapper — scans text/file for threats, logs results
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

# Pass all args through to origin-fortress scan
OUTPUT=$($ORIGIN_FORTRESS scan "$@" 2>&1) || true

# Log
echo "[$TIMESTAMP] scan $*" >> "$LOGFILE"
echo "$OUTPUT" >> "$LOGFILE"
echo "---" >> "$LOGFILE"

# Print output
echo "$OUTPUT"

# Exit non-zero if CRITICAL or HIGH found
if echo "$OUTPUT" | grep -qiE '"severity"\s*:\s*"(critical|high)"' || \
   echo "$OUTPUT" | grep -qiE '(CRITICAL|HIGH)'; then
  echo "⚠️  CRITICAL/HIGH threat detected!" >&2
  exit 1
fi
