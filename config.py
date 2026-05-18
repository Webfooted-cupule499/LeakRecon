import os
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """
    Enterprise Configuration Configuration Settings for LeakRecon.
    
    Manages environment variables, default application configurations,
    and threshold tunings for the asynchronous Tor engine.
    Utilizes Pydantic BaseSettings for strict type validation and context safety.
    """
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    # Proxy Configuration (Tor)
    TOR_PROXY_HOST: str = Field(default="torproxy", description="Tor SOCKS5 proxy host")
    TOR_PROXY_PORT: int = Field(default=9050, description="Tor SOCKS5 proxy port")
    
    # Timeout Settings
    ONION_TIMEOUT: int = Field(default=20, description="Timeout for .onion domain requests in seconds")
    CLEARNET_TIMEOUT: int = Field(default=10, description="Timeout for clearnet domain requests in seconds")
    
    # Retry and Concurrency Mechanisms
    MAX_RETRIES: int = Field(default=2, description="Maximum number of retries for failed network requests")
    RETRY_BACKOFF: float = Field(default=2.0, description="Backoff factor for retry delays")
    CIRCUIT_BREAKER_THRESHOLD: int = Field(default=2, description="Number of failures before a host is blacklisted")
    MAX_CONCURRENCY: int = Field(default=25, description="Maximum number of concurrent asynchronous tasks")
    
    # Application Context
    USER_AGENT: str = Field(
        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36",
        description="Default User-Agent string for HTTP requests"
    )
    
    # API Endpoints
    TOR_CHECK_URL: str = Field(
        default="https://check.torproject.org/api/ip",
        description="API endpoint to verify Tor network connectivity"
    )

    @property
    def tor_proxy_url(self) -> str:
        """
        Constructs and returns the SOCKS5 proxy URL based on the configuration.

        Returns:
            str: The formatted SOCKS5 URL.
        """
        return f"socks5://{self.TOR_PROXY_HOST}:{self.TOR_PROXY_PORT}"


# Global configuration instance
settings = Settings()
