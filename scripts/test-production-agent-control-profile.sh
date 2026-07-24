#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
compose="$root/docker/production/docker-compose.yml"
fixture=$(mktemp -d)
trap 'find "$fixture" -xdev -type f -delete; find "$fixture" -xdev -type l -delete; find "$fixture" -xdev -depth -type d -empty -delete' EXIT

# Default Product Core composition must not interpolate an Agent Control bind.
sed '/^DTX_AGENT_CONTROL_BIND=/d' "$root/docker/production/examples/x6.env.example" >"$fixture/production.env"
docker compose --env-file "$fixture/production.env" -f "$compose" config --services >"$fixture/default-services"
! grep -qx 'agent-control' "$fixture/default-services"
! grep -qx 'agent-control-ready' "$fixture/default-services"
for service in postgres bootstrap-roles migrate grant-roles verify-roles dtx-node node-ready realtime-gateway realtime-ready caddy; do
    grep -qx "$service" "$fixture/default-services"
done

docker compose --profile agent-control --env-file "$fixture/production.env" -f "$compose" config --services >"$fixture/agent-control-services"
grep -qx 'agent-control' "$fixture/agent-control-services"
grep -qx 'agent-control-ready' "$fixture/agent-control-services"

# The default installer and validator must not demand Agent service material.
! grep -q 'agent-control.json' "$root/scripts/production-stack/install.sh"
! grep -q 'secrets/agent-control' "$root/scripts/production-stack/install.sh"
! grep -q 'agent-control.json' "$root/scripts/production-stack/validate-files.sh"
! grep -q 'secrets/agent-control' "$root/scripts/production-stack/validate-files.sh"
! grep -q 'agent-control-ready' "$root/scripts/production-stack/verify.sh"
! grep -q 'DTX_AGENT_CONTROL_BIND' "$root/scripts/production-stack/host/provision-vnext"
! grep -q 'DTX_AGENT_CONTROL_BIND' "$root/scripts/production-stack/host/install-vnext"
! grep -q 'network_mode: service:agent-control' "$root/scripts/production-stack/host/provision-vnext"
! grep -q 'network_mode: service:agent-control' "$root/scripts/production-stack/host/install-vnext"
! grep -q "CONFIG/'agent-control.json'" "$root/scripts/production-stack/host/provision-vnext"
! grep -q "SECRETS/'agent-control'" "$root/scripts/production-stack/host/provision-vnext"

echo 'Agent Control profile compose checks passed'
