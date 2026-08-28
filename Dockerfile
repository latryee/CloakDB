# syntax=docker/dockerfile:1
FROM python:3.11-slim as base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -g 10001 cloakdb && \
    useradd -u 10001 -g cloakdb -m -s /bin/bash cloakdb

WORKDIR /app

COPY pyproject.toml /app/
COPY src/ /app/src/
COPY README.md /app/

RUN pip install --upgrade pip setuptools wheel && \
    pip install -e .

RUN chown -R cloakdb:cloakdb /app
USER cloakdb

ENTRYPOINT ["cloakdb"]
CMD ["--help"]
