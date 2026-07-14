FROM rust:1.97.0-bookworm AS build

WORKDIR /workspace
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/workspace/target \
    cargo build --release --locked \
    -p dtx-dev-migrate \
    -p dtx-identity-node \
    -p dtx-mailbox-node \
    && mkdir -p /artifacts \
    && cp /workspace/target/release/dtx-dev-migrate /artifacts/dtx-dev-migrate \
    && cp /workspace/target/release/dtx-identity-node /artifacts/dtx-identity-node \
    && cp /workspace/target/release/dtx-mailbox-node /artifacts/dtx-mailbox-node

FROM debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install --yes --no-install-recommends bash ca-certificates socat \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home dtx

COPY --from=build /artifacts/dtx-dev-migrate /usr/local/bin/dtx-dev-migrate
COPY --from=build /artifacts/dtx-identity-node /usr/local/bin/dtx-identity-node
COPY --from=build /artifacts/dtx-mailbox-node /usr/local/bin/dtx-mailbox-node
COPY docker/local/identity-entrypoint.sh /usr/local/bin/dtx-identity-local

RUN chmod 0555 /usr/local/bin/dtx-dev-migrate \
    /usr/local/bin/dtx-identity-node \
    /usr/local/bin/dtx-mailbox-node \
    /usr/local/bin/dtx-identity-local

USER dtx
