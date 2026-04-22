FROM oven/bun:1.3-slim AS build

WORKDIR /app
COPY package.json bun.lock* ./
RUN bun install --frozen-lockfile --production

COPY src/ src/
COPY tsconfig.json ./

# ── Runtime stage ──────────────────────────────────────
FROM oven/bun:1.3-slim

ARG VERSION=dev
LABEL org.opencontainers.image.title="Gatehouse"
LABEL org.opencontainers.image.description="Lightweight secrets vault for homelab AI agents"
LABEL org.opencontainers.image.source="https://github.com/bshandley/gatehouse"
LABEL org.opencontainers.image.licenses="AGPL-3.0-or-later"
LABEL org.opencontainers.image.version="${VERSION}"

# Install openssh-client for SSH certificate provider (ssh-keygen)
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r gatehouse && useradd -r -g gatehouse -d /app gatehouse

WORKDIR /app
COPY --from=build --chown=gatehouse:gatehouse /app /app

RUN mkdir -p /data /config/policies && \
    chown -R gatehouse:gatehouse /data /config

EXPOSE 3100

ENV GATEHOUSE_DATA_DIR=/data
ENV GATEHOUSE_CONFIG_DIR=/config
ENV GATEHOUSE_PORT=3100

VOLUME ["/data", "/config"]

USER gatehouse

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD bun -e "const r = await fetch('http://localhost:3100/health'); process.exit(r.ok ? 0 : 1)"

ENTRYPOINT ["bun", "run"]
CMD ["src/index.ts"]
