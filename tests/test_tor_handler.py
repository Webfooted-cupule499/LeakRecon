import pytest
from unittest.mock import patch, MagicMock, AsyncMock
from core.tor_handler import TorHandler
import asyncio

@pytest.fixture
def tor_handler():
    return TorHandler()

@pytest.mark.asyncio
async def test_get_successful_response(tor_handler):
    with patch("aiohttp.ClientSession.get") as mock_get:
        # Mock successful response
        mock_resp = AsyncMock()
        mock_resp.status = 200
        mock_resp.json = AsyncMock(return_value={"status": "success"})
        mock_resp.__aenter__.return_value = mock_resp
        
        mock_get.return_value = mock_resp

        # We must initialize the session first to avoid runtime warning
        await tor_handler._init_session()

        response = await tor_handler.get("http://example.com")
        assert response is not None
        assert response.status == 200
        data = await response.json()
        assert data["status"] == "success"

@pytest.mark.asyncio
async def test_verify_tor_connection_fail(tor_handler):
    # If connection fails, check returns False
    with patch.object(tor_handler, "get", return_value=None):
        result = await tor_handler.verify_tor_connection()
        assert result is False
