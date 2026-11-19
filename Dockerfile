# syntax=docker/dockerfile:1
# Images for the Go parts of netnoodle.
#   docker build --target server -t netnoodle/server .
#   docker build --target scan   -t netnoodle/scan .
#   docker build --target agent --output bin/linux .   (static nn-agent for Linux x86_64)
# The Rust agent and the host actor run on the host itself, not in a container.

FROM golang:1.26-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -trimpath -ldflags "-s -w" -o /out/nn-server ./cmd/nn-server \
 && go build -trimpath -ldflags "-s -w" -o /out/nn-scan ./cmd/nn-scan \
 && mkdir -p /out/var/lib/netnoodle/data /out/var/lib/nn-scan

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

# nn-agent: static Linux binary (musl). Export it with --output; it is not a service image.
FROM rust:1-alpine AS agent-build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY agent/ ./
RUN cargo build --release --locked -p nn-agent

FROM scratch AS agent
COPY --from=agent-build /src/target/release/nn-agent /nn-agent
