#!/usr/bin/env bash
set -euo pipefail
HOST=${1:-cti-decoy-01}
USER=${2:-ubuntu}
PORT=${3:-2222}
printf "Testing SSH to %s@%s:%s...\n" "$USER" "$HOST" "$PORT"
ssh -o BatchMode=yes -o ConnectTimeout=6 -p "$PORT" "$USER@$HOST" "echo ok" 2>/dev/null | grep -q ok && echo "SSH connectivity: OK" || { echo "SSH connectivity: FAILED" >&2; exit 1; }
