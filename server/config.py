"""Server configuration using Pydantic BaseSettings."""

from typing import List
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "CipherSecOps"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = Field(default=False, env="DEBUG")

    # Database
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://ciphersec:ciphersec@localhost:5432/ciphersecops",
        env="DATABASE_URL",
    )

    # Redis
    REDIS_URL: str = Field(default="redis://localhost:6379/0", env="REDIS_URL")

    # Kafka
    KAFKA_BOOTSTRAP_SERVERS: str = Field(
        default="localhost:9092", env="KAFKA_BOOTSTRAP_SERVERS"
    )
    KAFKA_TOPIC_TELEMETRY: str = Field(
        default="telemetry-events", env="KAFKA_TOPIC_TELEMETRY"
    )
    KAFKA_TOPIC_THREATS: str = Field(
        default="threat-detections", env="KAFKA_TOPIC_THREATS"
    )

    # JWT
    JWT_SECRET_KEY: str = Field(
        default="changeme-super-secret-jwt-key-at-least-32-chars",
        env="JWT_SECRET_KEY",
    )
    JWT_ALGORITHM: str = Field(default="HS256", env="JWT_ALGORITHM")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
        default=60, env="ACCESS_TOKEN_EXPIRE_MINUTES"
    )

    # Elasticsearch
    ELASTICSEARCH_URL: str = Field(
        default="http://localhost:9200", env="ELASTICSEARCH_URL"
    )
    ELASTICSEARCH_INDEX_TELEMETRY: str = "ciphersec-telemetry"
    ELASTICSEARCH_INDEX_THREATS: str = "ciphersec-threats"

    # CORS
    CORS_ORIGINS: List[str] = Field(
        default=[
            "http://localhost:3000",
            "http://localhost:8080",
            "http://127.0.0.1:3000",
        ],
        env="CORS_ORIGINS",
    )

    # Threat Intelligence API Keys
    ALIENVAULT_OTX_API_KEY: str = Field(default="", env="ALIENVAULT_OTX_API_KEY")
    ABUSEIPDB_API_KEY: str = Field(default="", env="ABUSEIPDB_API_KEY")
    VIRUSTOTAL_API_KEY: str = Field(default="", env="VIRUSTOTAL_API_KEY")

    # Notification
    SLACK_WEBHOOK_URL: str = Field(default="", env="SLACK_WEBHOOK_URL")
    PAGERDUTY_ROUTING_KEY: str = Field(default="", env="PAGERDUTY_ROUTING_KEY")

    # Risk thresholds
    RISK_THRESHOLD_MEDIUM: int = 30
    RISK_THRESHOLD_HIGH: int = 60
    RISK_THRESHOLD_CRITICAL: int = 85

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = True


settings = Settings()
