# Sandbox for running third-party MCP servers during a wallfacer campaign.
# Install phase runs with network; scan phase runs with --network none.
FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates git \
 && rm -rf /var/lib/apt/lists/*
COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /uvx /usr/local/bin/
ENV NPM_CONFIG_UPDATE_NOTIFIER=false NPM_CONFIG_FUND=false NO_UPDATE_NOTIFIER=1 UV_PYTHON_DOWNLOADS=never
WORKDIR /work
COPY wf-guard.js /usr/local/bin/wf-guard
RUN chmod +x /usr/local/bin/wf-guard
