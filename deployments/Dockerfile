FROM rust:1.88.0-alpine3.21 AS builder

RUN apk add --no-cache \
    pkgconfig \
    openssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY Cargo.toml Cargo.lock ./

COPY src ./src
COPY migrations ./migrations
COPY templates ./templates

RUN cargo build --release --locked

FROM alpine:3.21 AS runtime

RUN apk add --no-cache \
    ca-certificates \
    libssl3

RUN addgroup -S raigeki && adduser -S raigeki -G raigeki

WORKDIR /app

COPY --from=builder /app/target/release/raigeki /app/raigeki

RUN chown -R raigeki:raigeki /app

USER raigeki

ENV RUST_LOG=info
ENV RUST_BACKTRACE=1

CMD ["./raigeki"]