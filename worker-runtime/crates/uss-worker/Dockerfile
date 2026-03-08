FROM rust:1.90-bookworm AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    protobuf-compiler \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY contracts ./contracts
COPY worker-runtime ./worker-runtime

WORKDIR /src/worker-runtime/crates/uss-worker
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/worker-runtime/crates/uss-worker/target/release/uss-worker /usr/local/bin/uss-worker

WORKDIR /data
ENV USS_WORKER_DAEMON=true

ENTRYPOINT ["/usr/local/bin/uss-worker"]
