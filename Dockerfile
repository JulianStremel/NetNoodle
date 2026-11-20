# syntax=docker/dockerfile:1
# Images for the Go parts of netnoodle.
#   docker build --target server -t netnoodle/server .
#   docker build --target scan   -t netnoodle/scan .
#   docker build --target agent --output bin/linux .   (static nn-agent + nn-agent-helper for Linux x86_64)
# The Rust agent and the host actor run on the host itself, not in a container.

FROM golang:1.26-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags "-s -w" -o /out/nn-server ./cmd/nn-server \
 && go build -trimpath -ldflags "-s -w" -o /out/nn-scan ./cmd/nn-scan \
 && go build -trimpath -ldflags "-s -w" -o /out/nn-actor ./cmd/nn-actor \
 && mkdir -p /out/var/lib/netnoodle/data /out/var/lib/nn-scan /out/var/lib/nn-actor

# nn-server: web UI and API on 7443. Data (database, TLS key) in /var/lib/netnoodle/data.
FROM gcr.io/distroless/static-debian12:nonroot AS server
COPY --from=build --chown=65532:65532 /out/var/lib/netnoodle /var/lib/netnoodle
COPY --from=build /out/nn-server /usr/local/bin/nn-server
WORKDIR /var/lib/netnoodle
VOLUME /var/lib/netnoodle/data
EXPOSE 7443
ENTRYPOINT ["/usr/local/bin/nn-server"]
CMD ["-config", "/etc/netnoodle/netnoodle.json"]

# nn-scan: subnet scanner. Credentials in /var/lib/nn-scan.
FROM gcr.io/distroless/static-debian12:nonroot AS scan
COPY --from=build --chown=65532:65532 /out/var/lib/nn-scan /var/lib/nn-scan
COPY --from=build /out/nn-scan /usr/local/bin/nn-scan
WORKDIR /var/lib/nn-scan
VOLUME /var/lib/nn-scan
ENTRYPOINT ["/usr/local/bin/nn-scan"]
CMD ["run", "-config", "/etc/netnoodle/nn-scan.json"]

FROM gcr.io/distroless/static-debian12:nonroot AS actor
COPY --from=build --chown=65532:65532 /out/var/lib/nn-actor /var/lib/nn-actor
COPY --from=build /out/nn-actor /usr/local/bin/nn-actor
WORKDIR /var/lib/nn-actor
VOLUME /var/lib/nn-actor
ENTRYPOINT ["/usr/local/bin/nn-actor"]
CMD ["run", "-config", "/etc/netnoodle/nn-actor.json"]

# nn-agent and nn-agent-helper: static Linux binaries (musl).
# Export them with --output; this is not a service image.
FROM rust:1-alpine AS agent-base
RUN apk add --no-cache musl-dev && rustup component add clippy
WORKDIR /src
COPY agent/ ./

# Linux lint and tests. scripts/check.sh runs this stage when Docker is present.
FROM agent-base AS agent-check
RUN --mount=type=cache,target=/usr/local/cargo/registry     --mount=type=cache,target=/src/target     cargo clippy --locked --all-targets -q -- -D warnings && cargo test --locked -q

FROM agent-base AS agent-build
RUN --mount=type=cache,target=/usr/local/cargo/registry     --mount=type=cache,target=/src/target     cargo build --release --locked -p nn-agent  && mkdir /out && cp target/release/nn-agent target/release/nn-agent-helper /out/

FROM scratch AS agent
COPY --from=agent-build /out/ /
