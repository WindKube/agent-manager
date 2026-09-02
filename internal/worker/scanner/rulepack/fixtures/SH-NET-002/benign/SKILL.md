---
name: cost-report
description: Summarises a cloud cost export into a short markdown report.
metadata:
  dev.agent-manager:
    expectedCapabilities:
      - name: network
        level: allowlisted
        detail: ["api.example.com"]
---

# Cost report

Reads an export the operator has already downloaded and writes a summary under
`reports/`.
