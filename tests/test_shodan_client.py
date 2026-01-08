"""Tests for the Shodan client."""

from unittest.mock import Mock, patch

import pytest

from elasticsearch_finder.clients.shodan_client import ShodanClient


class TestShodanClient:
    """Tests for ShodanClient."""

    def test_init(self):
        """Test client initialization."""
        with patch("elasticsearch_finder.clients.shodan_client.shodan") as mock_shodan:
            client = ShodanClient("test_api_key")
            mock_shodan.Shodan.assert_called_once_with("test_api_key")
            assert client.api is not None

    def test_search_elasticsearch_basic(self):
        """Test basic elasticsearch search."""
        with patch("elasticsearch_finder.clients.shodan_client.shodan") as mock_shodan:
            mock_api = Mock()
            mock_api.search.return_value = {"matches": [{"ip_str": "1.2.3.4"}]}
            mock_shodan.Shodan.return_value = mock_api

            client = ShodanClient("test_api_key")
            results = client.search_elasticsearch()

            mock_api.search.assert_called_once_with("port:9200 json", page=1)
            assert len(results) == 1
            assert results[0]["ip_str"] == "1.2.3.4"

    def test_search_elasticsearch_with_country(self):
        """Test elasticsearch search with country filter."""
        with patch("elasticsearch_finder.clients.shodan_client.shodan") as mock_shodan:
            mock_api = Mock()
            mock_api.search.return_value = {"matches": []}
            mock_shodan.Shodan.return_value = mock_api

            client = ShodanClient("test_api_key")
            client.search_elasticsearch(country="US", page=2)

            mock_api.search.assert_called_once_with('port:9200 json country:"US"', page=2)

    def test_search_elasticsearch_api_error(self):
        """Test handling of API errors."""
        with patch("elasticsearch_finder.clients.shodan_client.shodan") as mock_shodan:
            mock_api = Mock()
            mock_shodan.APIError = Exception
            mock_api.search.side_effect = mock_shodan.APIError("API Error")
            mock_shodan.Shodan.return_value = mock_api

            client = ShodanClient("test_api_key")

            with pytest.raises(Exception) as exc_info:
                client.search_elasticsearch()

            assert "Shodan API error" in str(exc_info.value)

    def test_parse_result_valid(self):
        """Test parsing a valid result."""
        with patch("elasticsearch_finder.clients.shodan_client.shodan"):
            client = ShodanClient("test_api_key")

            result = {
                "ip_str": "1.2.3.4",
                "elastic": {
                    "cluster": {
                        "cluster_name": "test-cluster",
                        "status": "green",
                        "nodes": {"count": {"total": 3}},
                        "indices": {"store": {"size_in_bytes": 1024}},
                    }
                },
                "location": {"country_code": "US"},
                "org": "Test Org",
                "data": "Elastic Indices: test",
            }

            parsed = client.parse_result(result)

            assert parsed["host"] == "1.2.3.4"
            assert parsed["port"] == 9200
            assert parsed["source"] == "shodan"
            assert parsed["cluster_name"] == "test-cluster"
            assert parsed["status"] == "green"
            assert parsed["country"] == "US"
            assert parsed["number_nodes"] == 3
            assert parsed["organization"] == "Test Org"
            assert parsed["cluster_size_bytes"] == 1024

    def test_parse_result_missing_data(self):
        """Test parsing a result with missing elastic data."""
        with patch("elasticsearch_finder.clients.shodan_client.shodan"):
            client = ShodanClient("test_api_key")

            result = {
                "ip_str": "1.2.3.4",
                "location": {"country_code": "US"},
            }

            parsed = client.parse_result(result)

            assert parsed["host"] == "1.2.3.4"
            assert parsed["cluster_name"] == ""
            assert parsed["status"] == ""
            assert parsed["number_nodes"] == 0

    def test_get_host_info(self):
        """Test getting host information."""
        with patch("elasticsearch_finder.clients.shodan_client.shodan") as mock_shodan:
            mock_api = Mock()
            mock_api.host.return_value = {"org": "Test Org", "ports": [9200]}
            mock_shodan.Shodan.return_value = mock_api

            client = ShodanClient("test_api_key")
            info = client.get_host_info("1.2.3.4")

            mock_api.host.assert_called_once_with("1.2.3.4")
            assert info["org"] == "Test Org"

    def test_get_host_info_error(self):
        """Test handling host info errors."""
        with patch("elasticsearch_finder.clients.shodan_client.shodan") as mock_shodan:
            mock_api = Mock()
            mock_shodan.APIError = Exception
            mock_api.host.side_effect = mock_shodan.APIError("Not found")
            mock_shodan.Shodan.return_value = mock_api

            client = ShodanClient("test_api_key")
            info = client.get_host_info("1.2.3.4")

            assert info is None
