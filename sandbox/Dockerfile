FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        nodejs \
        npm \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir uv

WORKDIR /opt/agent-scan
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

WORKDIR /
