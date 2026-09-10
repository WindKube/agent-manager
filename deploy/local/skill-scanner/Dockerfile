# The second scan engine. Third-party infrastructure under constitution
# principle VI: a pinned pip install of an Apache 2.0 package and the tool's own
# entrypoint, with no code this project writes.
#
# It holds no credential of this system's and its compose network has no egress.
# That placement is the point: the engine parses attacker-controlled input with a
# C extension (YARA), so the process doing it must not be the one holding the
# database credential and the object-store key.
FROM python:3.13-slim

ARG SKILL_SCANNER_VERSION=2.1.0

RUN pip install --no-cache-dir "cisco-ai-skill-scanner==${SKILL_SCANNER_VERSION}" \
    && adduser --system --no-create-home --disabled-login engine

USER engine

EXPOSE 8000

ENTRYPOINT ["skill-scanner-api", "--host", "0.0.0.0", "--port", "8000"]
