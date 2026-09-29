# Build Stage. Pin the patched toolchain used by release builds.
FROM golang:1.25-bookworm AS builder

WORKDIR /app

# Copy dependency files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the application
# CGO_ENABLED=0 results in a static binary (no dependencies on host libraries)
# GOOS=linux ensures we build for Linux regardless of the host OS
ARG VERSION=dev
ARG BUILD_DATE=unknown
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X github.com/divinelab-io/aegis/internal/core/admin.Version=${VERSION} -X github.com/divinelab-io/aegis/internal/core/admin.BuildDate=${BUILD_DATE}" -o /aegis ./cmd/aegis-server && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.Version=${VERSION} -X main.BuildDate=${BUILD_DATE}" -o /aegis-updater ./cmd/aegis-updater && \
    mkdir -p /runtime/data/tls/certs /runtime/data/tls/acme

# Run Stage
FROM gcr.io/distroless/static-debian12

WORKDIR /var/lib/aegis

# Copy binary from builder
COPY --from=builder /aegis /aegis
COPY --from=builder /aegis-updater /aegis-updater
COPY --from=builder --chown=nonroot:nonroot /runtime/ /var/lib/aegis/
COPY --from=builder --chown=nonroot:nonroot /app/web/ /var/lib/aegis/web/
COPY --from=builder --chown=nonroot:nonroot /app/data/rules/ /var/lib/aegis/data/rules/

# Copy configuration (if present in context, otherwise user must mount it)
# Mount the installation config at /var/lib/aegis/config.yaml or set
# AEGIS_CONFIG to another mounted path.

EXPOSE 8080 8081

VOLUME ["/var/lib/aegis/data"]

USER nonroot:nonroot

ENTRYPOINT ["/aegis"]
