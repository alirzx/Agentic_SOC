FROM python:3.11-slim AS base

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Debian APT mirrors are independent of Python's Liara/Chabokan PyPI indexes.
# Debian signed Release metadata remains validated by APT; do not use trusted=yes.
# The official Debian mirror directory lists regional alternatives. Check GET
# reachability from the Docker host before building.
ARG APT_DEBIAN_MIRROR=https://archive.debian.petiak.ir/debian
ARG APT_SECURITY_MIRROR=https://deb.debian.org/debian-security
RUN set -eux; \
    case "$APT_DEBIAN_MIRROR:$APT_SECURITY_MIRROR" in \
      https://*:https://*) ;; \
      *) echo "APT mirrors must use HTTPS" >&2; exit 1 ;; \
    esac; \
    sed -i \
      -e "s|http://deb.debian.org/debian-security|$APT_SECURITY_MIRROR|g" \
      -e "s|http://deb.debian.org/debian|$APT_DEBIAN_MIRROR|g" \
      /etc/apt/sources.list.d/debian.sources; \
    apt-get -o Acquire::Retries=1 \
      -o Acquire::http::Timeout=25 \
      -o Acquire::https::Timeout=25 update; \
    apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libgdk-pixbuf-2.0-0 \
    shared-mime-info; \
    rm -rf /var/lib/apt/lists/*

# Select ONE trusted Python package mirror for both pip and Poetry.
# Liara is default; override PYPI_INDEX_URL with Chabokan if required.
ARG PYPI_INDEX_URL=https://package-mirror.liara.ir/repository/pypi/simple/
ENV PIP_INDEX_URL=${PYPI_INDEX_URL} \
    PIP_DEFAULT_TIMEOUT=40 \
    PIP_RETRIES=2 \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_NO_INTERACTION=1

RUN python -m pip install --no-cache-dir "poetry==2.5.1"

COPY pyproject.toml poetry.lock* ./

# Resolve from the selected mirror. Source changes alter Poetry's lock hash:
# refresh only INSIDE the build, then install the resolved package set.
# Fail rather than silently installing a drifting/incomplete pip fallback.
RUN poetry source add --priority=primary build-index "${PYPI_INDEX_URL}" \
    && poetry lock \
    && poetry install --only main --no-root --no-ansi \
    && python -m pip check

COPY . .

EXPOSE 8000

# Use a tiny Python wrapper (app.scripts.serve) that pre-binds a dual-stack
# IPv6 socket with IPV6_V6ONLY=0 and hands the fd to uvicorn via --fd.
#
# Why not just `uvicorn --host ::`? Python's asyncio explicitly sets
# IPV6_V6ONLY=1 on IPv6 sockets it creates, so binding to "::" only accepts
# IPv6 connections. On Fly we need BOTH: IPv6 for 6PN private traffic
# (aisoc-demo-api.internal from the web app) AND IPv4 for fly-proxy's public
# /health checks against api.tryaisoc.com (which speak IPv4 to 127.0.0.1).
# Pre-binding lets us turn IPV6_V6ONLY off so a single socket serves both.
CMD ["python", "-m", "app.scripts.serve"]
