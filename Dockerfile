# One image, four roles. The role is chosen at run time by subcommand
# (constitution principle I), never by a separate build.
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


# The migrator, built with `--target migrate`. It is deliberately NOT the last
# stage: a bare `docker build .` and compose.yaml's own `build:` must keep
# producing the serving image, and BuildKit skips a stage nothing depends on, so
# this and the atlas stage cost an ordinary build nothing.
#
# It exists because the serving image is distroless with one binary in it, so the
# .sql files and atlas.sum are not in it and Atlas cannot track a revision it
# cannot read. Without this image a deployment has to get the migrations from
# somewhere else — which in practice meant a git clone at deploy time, pinned to a
# commit by hand and free to disagree with the image it migrates for. Here the
# files and the binary come from one build of one commit and cannot drift.
#
# Alpine rather than distroless: two programs have to run in order, and expressing
# "then" needs a shell.
FROM arigaio/atlas:1.3.2-community-alpine AS atlas

FROM alpine:3.22 AS migrate

# For a deployment whose DSN asks for TLS. The alpine base ships none.
RUN apk add --no-cache ca-certificates \
    && adduser --system --no-create-home --disabled-password migrate

COPY --from=atlas /bin/atlas /usr/local/bin/atlas
COPY --from=build /out/agent-manager /usr/local/bin/agent-manager
COPY internal/store/migrations /migrations
COPY deploy/migrate/migrate.sh /usr/local/bin/migrate

USER migrate

ENTRYPOINT ["/usr/local/bin/migrate"]


FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/agent-manager /usr/local/bin/agent-manager

USER nonroot:nonroot

# The container has no shell, which is why `healthcheck` is a subcommand of the
# binary rather than a curl invocation (FR-058).
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD ["/usr/local/bin/agent-manager", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/agent-manager"]
CMD ["serve", "api"]
