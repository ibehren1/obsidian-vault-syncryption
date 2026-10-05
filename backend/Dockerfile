# syntax=docker/dockerfile:1

# Build: install the locked dependencies and the server into /app/.venv.
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS build
ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy UV_PYTHON_DOWNLOADS=0
WORKDIR /app
COPY pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv uv sync --locked --no-dev --no-install-project
COPY README.md ./
COPY src ./src
RUN --mount=type=cache,target=/root/.cache/uv uv sync --locked --no-dev --no-editable

# Litestream, checked against the release checksums.
FROM debian:bookworm-slim AS litestream
ARG TARGETARCH
ARG LITESTREAM_VERSION=0.5.17
ARG LITESTREAM_SHA256_AMD64=cfb371176d164437ae869f8351cfde49bd1804ae71c61923f75c9cba9c9c006d
ARG LITESTREAM_SHA256_ARM64=f8ca4a050095c1efbda2c4365172e61bf9d955ea0d9ac42f448b52e51819baa5
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) arch=x86_64; sum=$LITESTREAM_SHA256_AMD64 ;; \
      arm64) arch=arm64; sum=$LITESTREAM_SHA256_ARM64 ;; \
      *) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    file="litestream-${LITESTREAM_VERSION}-linux-${arch}.tar.gz"; \
    curl -fsSLo "/tmp/$file" "https://github.com/benbjohnson/litestream/releases/download/v${LITESTREAM_VERSION}/$file"; \
    echo "$sum  /tmp/$file" | sha256sum -c -; \
    tar -xzf "/tmp/$file" -C /usr/local/bin litestream

FROM caddy:2.11 AS caddy

# Runtime: Python, the virtualenv, Caddy and Litestream.
FROM python:3.12-slim-bookworm
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    XDG_CONFIG_HOME=/tmp/config \
    XDG_DATA_HOME=/data
COPY --from=build /app/.venv /app/.venv
COPY --from=litestream /usr/local/bin/litestream /usr/local/bin/litestream
COPY --from=caddy /usr/bin/caddy /usr/local/bin/caddy
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
VOLUME /data
EXPOSE 80 443 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s \
    CMD ["python", "-m", "syncryption_server", "health"]
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
