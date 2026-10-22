# syntax=docker/dockerfile:1.4

# ==============================================================================
# Stage 1: Build & Verification Environment
# ==============================================================================
FROM rust:bookworm AS builder

WORKDIR /workspace

# Copy workspace configuration and sources
COPY Cargo.toml Cargo.lock ./
COPY proto/ proto/
COPY crates/ crates/

# Build release binary with full optimizations (LTO, strip)
RUN cargo build --release --bin ggagent && \
    strip /workspace/target/release/ggagent

# ==============================================================================
# Stage 2: Hardened Distroless Non-Root Runtime Substrate
# ==============================================================================
FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

LABEL org.opencontainers.image.title="ckodex-ggagent-cli" \
      org.opencontainers.image.description="CKODEX Cleanroom Google Agents & A2A CLI Runtime with 77 Subagent Strategies" \
      org.opencontainers.image.vendor="CKODEX Architecture Team" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/ckodex/ckodex-ggagent-cli"

# Copy stripped binary from builder
COPY --from=builder --chown=nonroot:nonroot /workspace/target/release/ggagent /usr/local/bin/ggagent

# Hardened security defaults: unprivileged nonroot (UID:GID 65534:65534)
USER nonroot:nonroot
WORKDIR /home/nonroot

# Expose default HTTP/SSE/JSON-RPC service port
EXPOSE 8080

# Run playground and A2A/ARD endpoints
ENTRYPOINT ["/usr/local/bin/ggagent"]
CMD ["playground", "--port", "8080"]
