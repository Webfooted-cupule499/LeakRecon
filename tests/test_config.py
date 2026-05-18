import pytest
from config import Settings

def test_settings_defaults():
    settings = Settings()
    assert settings.TOR_PROXY_HOST == "127.0.0.1"
    assert settings.TOR_PROXY_PORT == 9050
    assert settings.MAX_CONCURRENCY == 10
    assert settings.REQUEST_TIMEOUT == 30
    assert settings.RETRY_LIMIT == 3

def test_tor_proxy_url():
    settings = Settings()
    # default host/port is 127.0.0.1:9050
    assert settings.get_proxy_url() == "socks5://127.0.0.1:9050"

def test_custom_settings():
    settings = Settings(TOR_PROXY_PORT=9150, REQUEST_TIMEOUT=15)
    assert settings.TOR_PROXY_PORT == 9150
    assert settings.REQUEST_TIMEOUT == 15
    assert settings.get_proxy_url() == "socks5://127.0.0.1:9150"
