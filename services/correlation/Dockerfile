FROM python:3.11-slim

WORKDIR /app

RUN pip install poetry==1.7.1 && \
    poetry config virtualenvs.create false

COPY pyproject.toml ./

# Keep the pip fallback list in lockstep with pyproject.toml. Unlike fusion the
# dependency set is small and pure-Python, so the fallback is cheap insurance
# against a transient Poetry/registry failure.
RUN set -eux; \
    if poetry install --no-interaction --no-ansi --without dev --no-root; then \
        echo "[correlation] poetry install succeeded"; \
    else \
        echo "[correlation] poetry install failed; using pip fallback"; \
        pip install --no-cache-dir \
            "fastapi>=0.109,<0.110" \
            "uvicorn[standard]>=0.27,<0.28" \
            "pydantic>=2.5,<3" \
            "pydantic-settings>=2.1,<3" \
            "asyncpg>=0.30,<0.31" \
            "httpx>=0.26,<0.27" \
            "structlog>=24.1,<25" \
            "prometheus-client>=0.19,<0.20" \
            "neo4j>=5.14,<6"; \
    fi

COPY app/ ./app/

EXPOSE 8010

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8010"]
