#!/bin/bash
set -Eeuo pipefail
DIRECT_SHA256=79c9840b0aab10bf8f74e44aa401d1c65da59d908d4880340601fdb4fcae167a
BASE=https://raw.githubusercontent.com/dinhnhanmta/amneziawg-easy-relay/main
[ "$(id -u)" -eq 0 ] || { echo 'Run as root'; exit 1; }
for tool in curl sha256sum python3; do
  command -v "$tool" >/dev/null || { echo "Missing $tool" >&2; exit 1; }
done
if ! command -v iptables >/dev/null || ! command -v ip >/dev/null || ! command -v sysctl >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y iptables iproute2 procps
fi
work=$(mktemp -d)
trap 'rm -f -- "$work/direct-relay.py"; rmdir -- "$work"' EXIT
curl --proto '=https' --tlsv1.2 --retry 3 -fsSL "$BASE/direct-relay.py" -o "$work/direct-relay.py"
printf '%s  %s\n' "$DIRECT_SHA256" "$work/direct-relay.py" | sha256sum -c - >/dev/null
python3 "$work/direct-relay.py" "$@"
