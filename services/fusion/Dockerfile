FROM python:3.11-slim

WORKDIR /app

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
ENV PATH="/app/.venv/bin:${PATH}"

COPY app/ ./app/

EXPOSE 8003

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8003"]
