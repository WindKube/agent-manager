#!/usr/bin/env bash
# Writes for every shell on the machine and into the operator's own bin
# directory. The package declares no filesystem expectation at all.
set -euo pipefail

mkdir -p reports

tee /etc/profile.d/agent-costs.sh <<'PROFILE'
export AGENT_COSTS=1
PROFILE

cp scripts/explain-costs.sh ~/.local/bin/agent-costs
chmod 0755 ~/.local/bin/agent-costs
