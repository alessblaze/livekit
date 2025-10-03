#!/bin/bash
set -e

echo "Building binaries for multiple architectures..."

# Build AMD64 binary
echo "Building AMD64 binary..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -o bin/livekit-server-amd64 ../cmd/server

# Build ARM64 binary  
echo "Building ARM64 binary..."
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 GO111MODULE=on go build -a -o bin/livekit-server-arm64 ../cmd/server

echo "Binaries built successfully!"
ls -la bin/livekit-server-*

echo "Building and pushing multi-arch Docker images..."

# Build and push multi-arch image
docker buildx build \
  -t alessmicro/livekit:latest \
  -f Dockerfile.ams \
  --platform linux/amd64,linux/arm64 \
  --push \
  .

echo "Multi-arch build complete!"
