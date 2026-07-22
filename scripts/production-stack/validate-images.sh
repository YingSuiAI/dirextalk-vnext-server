#!/usr/bin/env bash
set -euo pipefail

if (( $# != 0 )); then
    echo 'usage: validate-images.sh' >&2
    exit 2
fi
python3 /usr/local/lib/dirextalk/validate-production-images.py \
    /etc/dirextalk/vnext/config/production.env
