FROM python:3.11-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Keep in lockstep with pyproject.toml [tool.poetry.dependencies].
RUN pip install --no-cache-dir \
    "fastapi>=0.111,<0.140" \
    "uvicorn[standard]>=0.29,<0.52" \
    "pydantic>=2.7,<2.14" \
    "cryptography>=42,<50" \
    "httpx>=0.27,<0.29"

COPY app/ app/

EXPOSE 8010

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8010"]
