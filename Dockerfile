# One image, every role. The role is chosen at run time by subcommand
# (constitution principle I), never by a separate build — and that now includes
# the migration job, which is why atlas, River's CLI, the .sql files and the
# script that drives them are in here beside the binary. A deployment pulls one
# tag and cannot end up with a binary and a schema from two different commits.
#
# The base is alpine rather than distroless because of that script: the migration
# job runs the two tools directly, which needs a shell. What the serving roles
# lose by it is a smaller attack surface, and what they keep is the thing that
# mattered more — one image, one tag, one build.
#
# Generated output — templ's _templ.go and Tailwind's app.css — is committed, so
# this build needs neither templ nor the Tailwind binary and therefore no Node.
# CI regenerates and fails on a diff, which is what keeps the committed output honest.

FROM golang:1.26.6-alpine AS build

ARG VERSION=dev
ARG COMMIT=none
ARG BUILD_DATE=unknown

WORKDIR /src

RUN apk add --no-cache ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w \
        -X agent-manager/internal/cli.Version=${VERSION} \
        -X agent-manager/internal/cli.Commit=${COMMIT} \
        -X agent-manager/internal/cli.Date=${BUILD_DATE}" \
      -o /out/agent-manager ./cmd/agent-manager

# River's own CLI, built from this module's tool directive, so its version is
# github.com/riverqueue/river's version in go.mod and the two cannot drift: a CLI
# that migrated the queue past what the library expects would be found out at the
# first job insert rather than here.
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" \
      -o /out/river github.com/riverqueue/river/cmd/river


# Atlas applies the versioned .sql files and keeps the revision ledger. Taken as
# a binary rather than run as its own image, so the migration job is one
# container running one script. The queue's other half, River's CLI, is built
# above from this same module.
FROM arigaio/atlas:1.3.2-community-alpine AS atlas


FROM alpine:3.22

RUN apk add --no-cache ca-certificates \
    && adduser --system --no-create-home --disabled-password agent-manager

COPY --from=build /out/agent-manager /usr/local/bin/agent-manager
COPY --from=build /out/river /usr/local/bin/river
COPY --from=atlas /bin/atlas /usr/local/bin/atlas
COPY internal/store/migrations /migrations
COPY deploy/migrate/migrate.sh /usr/local/bin/migrate

USER agent-manager

# `healthcheck` is a subcommand of the binary rather than a curl invocation
# (FR-058), so the probe needs nothing in the image but the binary itself.
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD ["/usr/local/bin/agent-manager", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/agent-manager"]
CMD ["serve", "api"]
