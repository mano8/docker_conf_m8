#!/usr/bin/env bash
#   export DOCKER_HOST_IP=10.254.254.1
set -euo pipefail

# Check that DOCKER_HOST_IP is set
if [[ -z "${DOCKER_HOST_IP:-}" ]]; then
  echo "ERROR: DOCKER_HOST_IP is not set." >&2
  exit 1
fi

# Regex for simple IPv4 format
ipv4_regex='^([0-9]{1,3}\.){3}[0-9]{1,3}$'

if [[ ! $DOCKER_HOST_IP =~ $ipv4_regex ]]; then
  echo "ERROR: DOCKER_HOST_IP ($DOCKER_HOST_IP) is not a valid IPv4 format." >&2
  exit 1
fi

# Split into octets and check numeric range
IFS='.' read -r oct1 oct2 oct3 oct4 <<< "$DOCKER_HOST_IP"
for octet in "$oct1" "$oct2" "$oct3" "$oct4"; do
  if (( octet < 0 || octet > 255 )); then
    echo "ERROR: Octet $octet out of range in DOCKER_HOST_IP." >&2
    exit 1
  fi
done

# All checks passed
echo "DOCKER_HOST_IP is valid: $DOCKER_HOST_IP"
exit 0