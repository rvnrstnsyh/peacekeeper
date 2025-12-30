#!/usr/bin/env sh
set -e

# -----------------------------
# Directories
# -----------------------------
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PROTO_ROOT="$ROOT_DIR/proto"
OUT_DIR="$ROOT_DIR/src/infra/grpc/stubs"
BIN_DIR="$ROOT_DIR/node_modules/.bin"

# -----------------------------
# Create output folder if missing
# -----------------------------
# Works on Linux, macOS, Windows (Git Bash / WSL)
mkdir -p "$OUT_DIR"

# -----------------------------
# Detect OS for protoc-gen-ts_proto
# -----------------------------
TS_PROTO_PLUGIN="$BIN_DIR/protoc-gen-ts_proto"
if [ -f "$TS_PROTO_PLUGIN.cmd" ]; then
  TS_PROTO_PLUGIN="$TS_PROTO_PLUGIN.cmd"
fi

# -----------------------------
# Generate TypeScript gRPC stubs
# -----------------------------
"$BIN_DIR/grpc_tools_node_protoc" \
  --proto_path="$PROTO_ROOT" \
  --plugin=protoc-gen-ts_proto="$TS_PROTO_PLUGIN" \
  --ts_proto_out="$OUT_DIR" \
  --ts_proto_opt=outputServices=grpc-js,esModuleInterop=true \
  "$PROTO_ROOT/v0/contract.proto"

echo "gRPC TypeScript stubs generated successfully to $OUT_DIR"
