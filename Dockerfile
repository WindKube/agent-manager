# One image, four roles. The role is chosen at run time by subcommand
# (constitution principle I), never by a separate build.
#
# Generated output — templ's _templ.go and Tailwind's app.css — is committed, so
# this build needs neither templ nor the Tailwind binary and therefore no Node.
# CI regenerates and fails on a diff, which is what keeps the committed output honest.

FROM golang:1.26.5-alpine AS build

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


FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/agent-manager /usr/local/bin/agent-manager

USER nonroot:nonroot

# The container has no shell, which is why `healthcheck` is a subcommand of the
# binary rather than a curl invocation (FR-058).
HEALTHCHECK --interval=15s --timeout=5s --start-period=20s --retries=3 \
  CMD ["/usr/local/bin/agent-manager", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/agent-manager"]
CMD ["serve", "api"]
