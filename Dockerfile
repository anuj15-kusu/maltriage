# syntax=docker/dockerfile:1
#
# Two stages: a builder with compilers (in case a wheel is missing for the target
# architecture) and a slim runtime that contains no build tooling at all.

# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends build-essential \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src

RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --upgrade pip \
 && /opt/venv/bin/pip install .

# ---------------------------------------------------------------------------
FROM python:3.12-slim-bookworm AS runtime

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/tmp

# Unprivileged account: parsers chew on hostile input, so nothing runs as root.
RUN groupadd --gid 10001 triage \
 && useradd --uid 10001 --gid triage --no-create-home --shell /usr/sbin/nologin triage

COPY --from=builder /opt/venv /opt/venv

# The working directory carries everything the tool resolves at runtime:
# rules/ (YARA), templates/ (HTML report) and, optionally, .env.
WORKDIR /work
COPY pyproject.toml README.md ./
COPY rules ./rules
COPY templates ./templates

RUN mkdir -p /work/out /work/.cache /samples \
 && chown -R triage:triage /work/out /work/.cache \
 && chmod 0555 /work /work/rules /work/templates

USER 10001:10001

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD ["maltriage", "version"]

ENTRYPOINT ["maltriage"]
CMD ["--help"]
