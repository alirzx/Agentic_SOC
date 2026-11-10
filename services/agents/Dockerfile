FROM python:3.11-slim

WORKDIR /app

# System deps occasionally needed by transitive packages (qdrant fastembed,
# weasyprint, etc.). Keep the list small; expand only when poetry resolution
# proves a missing system library is required.
# Debian APT mirrors are independent of Python's Liara/Chabokan PyPI indexes.
# Debian signed Release metadata remains validated by APT; do not use trusted=yes.
# The official Debian mirror directory lists regional alternatives. Check GET
# reachability from the Docker host before building.
ARG APT_DEBIAN_MIRROR=https://archive.debian.petiak.ir/debian
ARG APT_SECURITY_MIRROR=https://mirror.dogado.de/debian-security
RUN set -eux; \
    case "$APT_DEBIAN_MIRROR:$APT_SECURITY_MIRROR" in \
      https://*:https://*) ;; \
      *) echo "APT mirrors must use HTTPS" >&2; exit 1 ;; \
    esac; \
    sed -i \
      -e "s|http://deb.debian.org/debian-security|$APT_SECURITY_MIRROR|g" \
      -e "s|http://deb.debian.org/debian|$APT_DEBIAN_MIRROR|g" \
      /etc/apt/sources.list.d/debian.sources; \
    # Missing signed security indexes must abort the build instead of \
    # falling through to an inconsistent OpenSSL/libpq dependency solver. \
    apt-get -o APT::Update::Error-Mode=any \
      -o Acquire::Retries=1 \
      -o Acquire::http::Timeout=25 \
      -o Acquire::https::Timeout=25 update; \
    apt-cache policy libssl-dev libssl3t64; \
    apt-get install -y --no-install-recommends \
    build-essential; \
    rm -rf /var/lib/apt/lists/*

# Select ONE trusted Python package mirror for both pip and Poetry.
# Liara is default; override PYPI_INDEX_URL with Chabokan if required.
ARG PYPI_INDEX_URL=https://package-mirror.liara.ir/repository/pypi/simple/
ENV PIP_INDEX_URL=${PYPI_INDEX_URL} \
    PIP_DEFAULT_TIMEOUT=40 \
    PIP_RETRIES=2 \
    POETRY_VIRTUALENVS_CREATE=true \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1

RUN python -m pip install --no-cache-dir "poetry==2.5.1"

COPY pyproject.toml poetry.lock* ./

# Resolve from the selected mirror. Source changes alter Poetry's lock hash:
# refresh only INSIDE the build, then install the resolved package set.
# Fail rather than silently installing a drifting/incomplete pip fallback.
RUN poetry source add --priority=primary build-index "${PYPI_INDEX_URL}" \
    && poetry lock \
    && poetry install --only main --no-root --no-ansi \
    && /app/.venv/bin/python -m pip check

# Runtime uses the isolated application environment, never Poetry tool packages.
ENV PATH="/app/.venv/bin:${PATH}" \
    PYTHONPATH="/app"

# Smoke-import the modules the orchestrator pulls in at module load time.
# Catches "image built but broken" cases at build time instead of runtime.
# Also assert that the langgraph version on disk exposes the ``START``
# sentinel — langgraph 0.0.x silently lacked it, which previously crashed the
# agents service at boot with ``ImportError: cannot import name 'START'``.
RUN python -c "import opentelemetry, langgraph, fastapi, sqlalchemy, asyncpg, redis, httpx, structlog, apscheduler, yaml, _cffi_backend; from cryptography.fernet import Fernet; from langgraph.graph import END, START, StateGraph"

COPY app/ ./app/
COPY scripts/check_remote_privacy_gateway.py ./scripts/check_remote_privacy_gateway.py
COPY scripts/check_protected_llm_flow.py ./scripts/check_protected_llm_flow.py
COPY app/scripts/privacy_provider_probe.py ./scripts/privacy_provider_probe.py

# Import the application module that first exposed the missing direct
# dependency. Keep this after COPY so the build validates the real import path.
RUN python -c "from app.security.credential_vault import CredentialVault"
RUN python -c "from app.privacy.rest_client import PrivacyGatewayRESTClient"

# Execute the real CLI entrypoint, not just an import from WORKDIR.
# This catches the historical ModuleNotFoundError for direct /app/scripts/*.py
# invocation without contacting DLP, Redis, Kafka, or any LLM provider.
RUN python /app/scripts/check_protected_llm_flow.py --help > /dev/null \
    && python /app/scripts/privacy_provider_probe.py --help > /dev/null

EXPOSE 8084

# Dual-stack entrypoint — see app/scripts/serve.py and the matching CMD in
# services/api/Dockerfile for the full rationale (Python's asyncio forces
# IPV6_V6ONLY=1 on `::` binds, which breaks Fly's IPv4 health checks).
CMD ["python", "-m", "app.scripts.serve"]
