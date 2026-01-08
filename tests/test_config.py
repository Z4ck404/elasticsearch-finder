"""Tests for configuration management."""

import os
from unittest.mock import patch

import pytest

from elasticsearch_finder.config import get_binaryedge_api_key, get_shodan_api_key


class TestConfig:
    """Tests for configuration functions."""

    def test_get_shodan_api_key_set(self):
        """Test getting Shodan API key when set."""
        with patch.dict(os.environ, {"SHODAN_API_KEY": "test_shodan_key"}):
            key = get_shodan_api_key()
            assert key == "test_shodan_key"

    def test_get_shodan_api_key_not_set(self):
        """Test getting Shodan API key when not set."""
        with patch.dict(os.environ, {}, clear=True):
            # Remove the key if it exists
            env = os.environ.copy()
            if "SHODAN_API_KEY" in env:
                del env["SHODAN_API_KEY"]
            with patch.dict(os.environ, env, clear=True):
                with pytest.raises(ValueError) as exc_info:
                    get_shodan_api_key()
                assert "SHODAN_API_KEY" in str(exc_info.value)

    def test_get_binaryedge_api_key_set(self):
        """Test getting BinaryEdge API key when set."""
        with patch.dict(os.environ, {"BINARYEDGE_API_KEY": "test_be_key"}):
            key = get_binaryedge_api_key()
            assert key == "test_be_key"

    def test_get_binaryedge_api_key_not_set(self):
        """Test getting BinaryEdge API key when not set."""
        with patch.dict(os.environ, {}, clear=True):
            env = os.environ.copy()
            if "BINARYEDGE_API_KEY" in env:
                del env["BINARYEDGE_API_KEY"]
            with patch.dict(os.environ, env, clear=True):
                with pytest.raises(ValueError) as exc_info:
                    get_binaryedge_api_key()
                assert "BINARYEDGE_API_KEY" in str(exc_info.value)
