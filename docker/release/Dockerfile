# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
FROM rust:1.97.0-bookworm@sha256:8fa55b2f3ddf97471ab6a767bfa3f37e6bad0986ba823e75fea57e2a2a5c3073 AS build

WORKDIR /workspace
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/workspace/target \
    rm -f \
        /workspace/target/release/dtx-node \
        /workspace/target/release/dtx-opaque-push-broker \
        /workspace/target/release/dtx-realtime-sync-gateway \
        /workspace/target/release/dtx-identity-provision \
        /workspace/target/release/dtx-agent-control \
    && \
    cargo build --release --locked \
        --package dtx-node \
        --package dtx-opaque-push-broker \
        --package dtx-realtime-sync-gateway \
        --package dtx-identity-node --bin dtx-identity-provision \
    && install -D -m 0555 /workspace/target/release/dtx-node /artifacts/dtx-node \
    && install -D -m 0555 /workspace/target/release/dtx-opaque-push-broker /artifacts/dtx-opaque-push-broker \
    && install -D -m 0555 /workspace/target/release/dtx-realtime-sync-gateway /artifacts/dtx-realtime-sync-gateway \
    && rm -f /workspace/target/release/dtx-agent-control \
    && cargo build --release --locked \
        --package dtx-agent-control-bin \
        --bin dtx-agent-control \
    && install -D -m 0555 /workspace/target/release/dtx-agent-control /artifacts/dtx-agent-control \
    && install -D -m 0555 /workspace/target/release/dtx-identity-provision /artifacts/dtx-identity-provision

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818 AS runtime

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN useradd --system --uid 10001 --create-home --home-dir /var/lib/dirextalk dtx

COPY --from=build /artifacts/dtx-node /usr/local/bin/dtx-node
COPY --from=build /artifacts/dtx-opaque-push-broker /usr/local/bin/dtx-opaque-push-broker
COPY --from=build /artifacts/dtx-realtime-sync-gateway /usr/local/bin/dtx-realtime-sync-gateway
COPY --from=build /artifacts/dtx-agent-control /usr/local/bin/dtx-agent-control
COPY --from=build /artifacts/dtx-identity-provision /usr/local/bin/dtx-identity-provision

ENV DTX_NODE_LISTEN=0.0.0.0:8443
EXPOSE 8443 9444 9448
STOPSIGNAL SIGTERM
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/dtx-node"]
