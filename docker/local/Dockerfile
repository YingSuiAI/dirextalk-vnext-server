FROM rust:1.97.0-bookworm AS build

WORKDIR /workspace
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/workspace/target \
    cargo build --release --locked \
    -p dtx-dev-migrate \
    -p dtx-node \
    && mkdir -p /artifacts \
    && cp /workspace/target/release/dtx-dev-migrate /artifacts/dtx-dev-migrate \
    && cp /workspace/target/release/dtx-node /artifacts/dtx-node

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends bash ca-certificates socat \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home dtx

COPY --from=build /artifacts/dtx-dev-migrate /usr/local/bin/dtx-dev-migrate
COPY --from=build /artifacts/dtx-node /usr/local/bin/dtx-node
COPY docker/local/node-entrypoint.sh /usr/local/bin/dtx-node-local

RUN chmod 0555 /usr/local/bin/dtx-dev-migrate \
    /usr/local/bin/dtx-node \
    /usr/local/bin/dtx-node-local

USER dtx
