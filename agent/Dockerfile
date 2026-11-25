# cb-agent: the Rust retrieval agent. Static-ish binary on distroless/cc,
# non-root, no shell.
# TODO before production: pin both base images by digest.
FROM rust:1.100-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
# cache dependencies separately from our code
RUN mkdir src && echo 'fn main(){}' > src/main.rs && cargo build --release --locked && rm -rf src
COPY src ./src
RUN touch src/main.rs && cargo build --release --locked

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/cb-agent /cb-agent
USER nonroot:nonroot
ENTRYPOINT ["/cb-agent"]
