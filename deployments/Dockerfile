FROM rust:1.83.0-alpine3.21 as builder

WORKDIR /app

COPY . .

RUN cargo build --release

FROM alpine:3.21

USER raigeki

COPY --from=builder /app/target/release/raigeki .

CMD ["./raigeki"]
