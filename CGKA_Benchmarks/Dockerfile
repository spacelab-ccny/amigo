# Start from official Rust image
FROM rust:1.84.1

# Work inside /app
WORKDIR /app

# Copy Cargo manifest first to cache deps
COPY Cargo.toml Cargo.lock ./

# Copy benches folder
COPY benches benches

# Copy source
COPY src src

# Download deps
RUN cargo fetch

# Run benchmarks by default
CMD ["cargo", "bench"]