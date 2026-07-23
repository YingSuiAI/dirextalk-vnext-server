#!/usr/bin/env bash
set -euo pipefail

if (( $# != 0 )); then
    echo 'Usage: bash scripts/check-production-stack.sh' >&2
    exit 2
fi
scripts/test-production-stack.sh
python3 tools/vnext-stack-bundle.py self-test --source-root .
python3 tools/test-vnext-stack-host.py
python3 tools/test-client-binding-release-artifacts.py
bash scripts/check-release-image.sh
echo 'production stack and four-binary release gates passed'
