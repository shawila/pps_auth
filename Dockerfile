FROM rust:1.78-slim AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock ./
# Pre-cache dependencies with stub binaries
RUN mkdir src && echo 'fn main(){}' > src/main.rs && \
    mkdir -p src/bin && echo 'fn main(){}' > src/bin/seed.rs && \
    echo 'pub fn placeholder(){}' > src/lib.rs && \
    cargo build --release && rm -rf src
COPY src ./src
COPY migrations ./migrations
COPY .sqlx ./.sqlx
RUN touch src/main.rs src/bin/seed.rs src/lib.rs && cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/pps_auth .
COPY --from=builder /app/target/release/seed .
EXPOSE 4000
CMD ["./pps_auth"]
