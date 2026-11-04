#!/bin/bash
set -Eeuo pipefail

# The checksum binds this entry point to its reviewed Python implementation.
INSTALLER_SHA256=604f05acf78da6d47f028ddd3cc2292237287f39f238e44945607bddf5b1ab64
BASE=https://raw.githubusercontent.com/dinhnhanmta/amneziawg-easy-relay/main

for tool in curl sha256sum python3; do
  command -v "$tool" >/dev/null || { echo "Missing $tool (Ubuntu 24.04 includes python3); install it first." >&2; exit 1; }
done
work=$(mktemp -d)
trap 'rm -f -- "$work/installer.py"; rmdir -- "$work"' EXIT
curl --proto '=https' --tlsv1.2 --retry 3 -fsSL "$BASE/installer.py" -o "$work/installer.py"
printf '%s  %s\n' "$INSTALLER_SHA256" "$work/installer.py" | sha256sum -c - >/dev/null
python3 "$work/installer.py" "$@"
