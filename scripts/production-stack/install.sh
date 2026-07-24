#!/usr/bin/env bash
set -euo pipefail

if (( $# != 0 )); then
    echo 'usage: install.sh' >&2
    exit 2
fi
if [[ ${EUID} -ne 0 ]]; then
    echo 'production stack install requires root' >&2
    exit 1
fi

install -d -o root -g 10001 -m 0750 /etc/dirextalk/vnext/secrets
install -d -o root -g root -m 0700 /etc/dirextalk/vnext/secrets/role-passwords
install -d -o root -g root -m 0755 /etc/dirextalk/vnext/config
install -d -o root -g 10001 -m 0750 /etc/dirextalk/vnext/tls
install -d -o root -g root -m 0750 /var/lib/dirextalk/vnext
install -o root -g root -m 0644 docker/production/Caddyfile /etc/dirextalk/vnext/config/Caddyfile
install -o root -g root -m 0644 docker/production/docker-compose.yml \
    /etc/dirextalk/vnext/config/production-compose.yml
install -d -o root -g root -m 0755 /usr/local/lib/dirextalk
install -o root -g root -m 0555 tools/validate-production-images.py \
    /usr/local/lib/dirextalk/validate-production-images.py
if [[ ! -e /etc/dirextalk/vnext/config/production.env ]]; then
    install -o root -g root -m 0644 docker/production/examples/production.env.example \
        /etc/dirextalk/vnext/config/production.env
fi
echo 'production stack directories installed; provision Product Core secrets and TLS files before bootstrap'
