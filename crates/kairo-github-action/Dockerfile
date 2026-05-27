FROM rust:1.80-slim-bookworm as builder

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates/kairo-core ./crates/kairo-core
COPY crates/kairo-github-action ./crates/kairo-github-action

RUN cargo build -p kairo-github-action --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/kairo-action /usr/local/bin/kairo-action

WORKDIR /github/workspace
ENTRYPOINT ["kairo-action"]
CMD ["github-action"]
