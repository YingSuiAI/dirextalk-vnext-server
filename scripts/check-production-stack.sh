#!/usr/bin/env bash
set -euo pipefail

if (( $# != 0 )); then
    echo 'Usage: bash scripts/check-production-stack.sh' >&2
    exit 2
fi
scripts/test-production-stack.sh
bash scripts/check-release-image.sh
echo 'production stack and four-binary release gates passed'
