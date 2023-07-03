FROM --platform=linux/amd64 rust:slim-bullseye AS rust-builder

RUN apt update
RUN apt install g++ -y

WORKDIR /app
COPY ../../csp-service/ csp-service
COPY ../../sqlite/ sqlite
RUN cd csp-service && cargo build --release
RUN mv /app/csp-service/target/release/csp-service csp-service-exec

FROM --platform=linux/amd64 debian:bullseye-slim
WORKDIR /app
COPY --from=rust-builder /app/csp-service-exec ./csp-service
CMD ["/app/csp-service-exec"]
