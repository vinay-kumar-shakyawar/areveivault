# Build from the repository root:  docker build -f server/Dockerfile -t arevei-server .
FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY core core
COPY server server
RUN cargo build --release --locked -p arevei-server \
 && strip target/release/arevei-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home /nonexistent --shell /usr/sbin/nologin arevei \
 && mkdir -p /data/attachments && chown arevei /data/attachments
COPY --from=build /src/target/release/arevei-server /usr/local/bin/arevei-server
USER arevei
ENV BIND_ADDR=0.0.0.0:8080 ATTACHMENT_DIR=/data/attachments
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/arevei-server"]
