FROM rust:1.88.0-alpine3.21 AS builder

RUN apk add --no-cache \
    musl-dev \
    pkgconfig \
    openssl-dev \
    build-base \
    cmake \
    openssl-libs-static

WORKDIR /app

COPY Cargo.toml .
COPY raigeki/Cargo.toml raigeki/Cargo.toml
COPY raigeki-error/Cargo.toml raigeki-error/Cargo.toml
COPY raigeki-tools/Cargo.toml raigeki-tools/Cargo.toml

COPY raigeki-error/src raigeki-error/src
COPY raigeki-tools/src raigeki-tools/src
COPY raigeki/src raigeki/src

RUN cargo build --release --package raigeki
FROM alpine:3.21 AS runtime

RUN apk add --no-cache \
    ca-certificates \
    libssl3

RUN addgroup -S raigeki && adduser -S raigeki -G raigeki

WORKDIR /app

COPY --from=builder /app/target/release/raigeki /app/raigeki

RUN chown -R raigeki:raigeki /app

USER raigeki

CMD ["./raigeki"]