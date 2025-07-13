# syntax=docker/dockerfile:1
# Bittensor Signer - Remote signing service for Bittensor

# Build stage
FROM golang:1.24-alpine AS build

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git make build-base

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build statically linked binaries to work in distroless
ENV CGO_ENABLED=0
RUN go build -ldflags="-w -s" -o bin/btsigner cmd/btsigner/main.go
RUN go build -ldflags="-w -s" -o bin/btclient cmd/btclient/main.go

# Verify the binaries exist and are executable
RUN ls -la bin/btsigner bin/btclient && \
    file bin/btsigner bin/btclient && \
    chmod +x bin/btsigner bin/btclient

# Server image
FROM gcr.io/distroless/static-debian11:nonroot AS server

WORKDIR /app

# Copy binary from build stage
COPY --from=build --chown=nonroot:nonroot /app/bin/btsigner /app/btsigner
COPY --from=build --chown=nonroot:nonroot /app/config-example.yaml /app/config.yaml

# Default volume for keystore
VOLUME ["/app/keystore"]

# Expose gRPC port
EXPOSE 50051
# Expose metrics port
EXPOSE 9090

USER nonroot:nonroot

# Default command when no other command is provided
# Note: Environment variables must be provided externally or via docker-compose
ENTRYPOINT ["/app/btsigner"]
CMD ["--config", "/app/config.yaml"]

# Client image
FROM gcr.io/distroless/static-debian12:nonroot AS client

WORKDIR /app

# Copy binary from build stage
COPY --from=build --chown=nonroot:nonroot /app/bin/btclient /app/btclient

USER nonroot:nonroot

ENTRYPOINT ["/app/btclient"] 