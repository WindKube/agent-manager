#!/usr/bin/env bash
# Writes only under the package's own directory.
set -euo pipefail

mkdir -p reports
tee reports/summary.txt
