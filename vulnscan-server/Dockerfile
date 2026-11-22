FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY vulnscan /usr/local/bin/vulnscan
RUN chmod +x /usr/local/bin/vulnscan \
    && vulnscan --version

EXPOSE 4954

ENTRYPOINT ["vulnscan"]
CMD ["server", "--listen", "0.0.0.0:4954"]