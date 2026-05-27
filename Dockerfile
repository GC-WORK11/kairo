# Build stage
FROM rust:1.75-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy workspace files
COPY Cargo.toml Cargo.lock ./
COPY rust-toolchain.toml ./

# Copy crate sources
COPY crates/kairo-core ./crates/kairo-core
COPY crates/kairo-server ./crates/kairo-server

# Build the binary
RUN cargo build --release -p kairo-server

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -u 1000 kairo

# Copy binary from builder
COPY --from=builder /app/target/release/kairo-server /app/kairo-server

# Set ownership
RUN chown -R kairo:kairo /app

USER kairo

EXPOSE 8080

ENV RUST_LOG=info

ENTRYPOINT ["/app/kairo-server"]
