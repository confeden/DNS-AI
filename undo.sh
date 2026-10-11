#!/bin/sh
# DNS-AI: undo the one-line setup.
#   curl -fsSL https://dns-ai.ru/undo.sh | sudo sh
# Only a wrapper: fetches setup.sh whole, then runs it with --undo, so the undo logic lives in one place.
set -eu
URL=https://dns-ai.ru/setup.sh
if command -v curl >/dev/null 2>&1; then s=$(curl -fsSL --max-time 20 "$URL")
else s=$(wget -qO- -T 20 "$URL"); fi
printf '%s\n' "$s" | sh -s -- --undo
