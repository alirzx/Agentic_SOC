"""Settings for the correlation engine."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        populate_by_name=True,
        extra="ignore",
    )

    # Service
    service_name: str = "aisoc-correlation"
    http_port: int = Field(default=8010, alias="HTTP_PORT")
    log_level: str = Field(default="INFO", alias="LOG_LEVEL")
    environment: str = Field(default="development", alias="ENVIRONMENT")

    # Storage
    database_url: str = Field(
        default="postgresql+asyncpg://aisoc:aisoc_secret@localhost:5432/aisoc",
        alias="DATABASE_URL",
    )
    db_pool_min: int = Field(default=2, alias="AISOC_CORRELATION_DB_POOL_MIN")
    db_pool_max: int = Field(default=15, alias="AISOC_CORRELATION_DB_POOL_MAX")

    # Ownership lock (doc §7.1). Each engine claims alerts atomically; the loser
    # walks away. ``claim_ttl_minutes`` lets a crashed run's claims be retried.
    owner: str = Field(default="graph_engine", alias="AISOC_CORRELATION_OWNER")
    claim_ttl_minutes: int = Field(default=60, alias="AISOC_CORRELATION_CLAIM_TTL_MINUTES")
    legacy_owner: str = Field(default="legacy", alias="AISOC_CORRELATION_LEGACY_OWNER")

    # Window / batching
    lookback_hours: int = Field(default=72, alias="AISOC_CORRELATION_LOOKBACK_HOURS")
    max_alerts_per_cycle: int = Field(default=5000, alias="AISOC_CORRELATION_MAX_ALERTS")
    poll_interval_seconds: int = Field(default=60, alias="AISOC_CORRELATION_POLL_SECONDS")
    worker_enabled: bool = Field(default=True, alias="AISOC_CORRELATION_WORKER_ENABLED")

    # Scoring
    theta: int = Field(default=3, alias="AISOC_CORRELATION_THETA")
    #: Minimum *distinct* canonical alerts a component needs to become a case.
    #: Two, because a case is a claim that several alerts agree: one detection
    #: repeated on twenty hosts (soft-dedup losers fold into one canonical
    #: alert) is a single event, and opening a case for it produced campaigns
    #: holding exactly one alert. Lower it to 1 only for corpora where a
    #: campaign genuinely is one alert repeated.
    min_case_alerts: int = Field(default=2, alias="AISOC_CORRELATION_MIN_CASE_ALERTS")
    normalizer_version: str = Field(default="2.0.0", alias="AISOC_CORRELATION_NORMALIZER_VERSION")

    # Graph (optional — the engine degrades to Postgres + in-memory)
    graph_enabled: bool = Field(default=True, alias="AISOC_GRAPH_ENABLED")
    neo4j_uri: str = Field(default="bolt://localhost:7687", alias="NEO4J_URI")
    neo4j_user: str = Field(default="neo4j", alias="NEO4J_USER")
    neo4j_password: str = Field(default="neo4j", alias="NEO4J_PASSWORD")
    neo4j_database: str = Field(default="neo4j", alias="NEO4J_DATABASE")

    # API client
    api_service_url: str = Field(default="http://localhost:8888", alias="API_SERVICE_URL")
    #: API key (``aisoc_…``) with the ``cases:write:correlation`` scope. Empty in
    #: development is allowed: the API's dev-mode auth resolves the demo tenant.
    correlation_api_token: str = Field(default="", alias="AISOC_CORRELATION_API_TOKEN")
    api_timeout_seconds: float = Field(default=15.0, alias="AISOC_CORRELATION_API_TIMEOUT")

    # Kafka (optional wake-up signal; Postgres remains the data source of record)
    kafka_enabled: bool = Field(default=False, alias="AISOC_CORRELATION_KAFKA_ENABLED")
    kafka_bootstrap_servers: str = Field(default="localhost:9092", alias="KAFKA_BOOTSTRAP_SERVERS")
    kafka_topic_alerts_raw: str = Field(default="aisoc.alerts.raw", alias="KAFKA_TOPIC_ALERTS_RAW")
    kafka_consumer_group: str = Field(default="aisoc-correlation-engine", alias="KAFKA_CONSUMER_GROUP")

    # Internal trigger endpoint
    internal_token: str = Field(default="", alias="AISOC_INTERNAL_TOKEN")

    @property
    def asyncpg_dsn(self) -> str:
        return self.database_url.replace("postgresql+asyncpg://", "postgresql://", 1)


settings = Settings()
