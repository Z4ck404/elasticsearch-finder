"""Tests for the BinaryEdge client."""

from unittest.mock import Mock, patch

import pytest

from elasticsearch_finder.clients.binaryedge_client import BinaryEdgeClient


class TestBinaryEdgeClient:
    """Tests for BinaryEdgeClient."""

    def test_init(self):
        """Test client initialization."""
        client = BinaryEdgeClient("test_api_key")
        assert client.api_key == "test_api_key"
        assert client.headers == {"X-Key": "test_api_key"}

    @patch("elasticsearch_finder.clients.binaryedge_client.requests")
    def test_search_elasticsearch_basic(self, mock_requests):
        """Test basic elasticsearch search."""
        mock_response = Mock()
        mock_response.json.return_value = {"total": 100, "events": []}
        mock_response.raise_for_status = Mock()
        mock_requests.get.return_value = mock_response

        client = BinaryEdgeClient("test_api_key")
        result = client.search_elasticsearch()

        mock_requests.get.assert_called_once_with(
            "https://api.binaryedge.io/v2/query/search",
            headers={"X-Key": "test_api_key"},
            params={"query": 'type:"elasticsearch"', "page": 1},
            timeout=15,
        )
        assert result["total"] == 100

    @patch("elasticsearch_finder.clients.binaryedge_client.requests")
    def test_search_elasticsearch_with_country(self, mock_requests):
        """Test elasticsearch search with country filter."""
        mock_response = Mock()
        mock_response.json.return_value = {"total": 50, "events": []}
        mock_response.raise_for_status = Mock()
        mock_requests.get.return_value = mock_response

        client = BinaryEdgeClient("test_api_key")
        client.search_elasticsearch(country="US", page=2)

        mock_requests.get.assert_called_once_with(
            "https://api.binaryedge.io/v2/query/search",
            headers={"X-Key": "test_api_key"},
            params={"query": 'type:"elasticsearch" country:"US"', "page": 2},
            timeout=15,
        )

    @patch("elasticsearch_finder.clients.binaryedge_client.requests")
    def test_search_elasticsearch_request_error(self, mock_requests):
        """Test handling of request errors."""
        mock_requests.get.side_effect = Exception("Connection error")
        mock_requests.RequestException = Exception

        client = BinaryEdgeClient("test_api_key")

        with pytest.raises(Exception) as exc_info:
            client.search_elasticsearch()

        assert "BinaryEdge API error" in str(exc_info.value)

    def test_get_total_results(self):
        """Test getting total results."""
        client = BinaryEdgeClient("test_api_key")

        response = {"total": 500, "events": []}
        assert client.get_total_results(response) == 500

        empty_response = {}
        assert client.get_total_results(empty_response) == 0

    def test_get_events(self):
        """Test getting events from response."""
        client = BinaryEdgeClient("test_api_key")

        events = [{"target": {"ip": "1.2.3.4"}}]
        response = {"total": 1, "events": events}
        assert client.get_events(response) == events

        empty_response = {}
        assert client.get_events(empty_response) == []

    def test_parse_event_valid(self):
        """Test parsing a valid event."""
        client = BinaryEdgeClient("test_api_key")

        event = {
            "target": {"ip": "1.2.3.4", "port": 9200},
            "origin": {"country": "US"},
            "result": {
                "data": {
                    "cluster_name": "test-cluster",
                    "cluster_nodes": 3,
                    "indices": [
                        {"index_name": "test-index", "docs": 1000, "size_in_bytes": 1024000},
                        {"index_name": "small-index", "docs": 10, "size_in_bytes": 0},
                    ],
                }
            },
        }

        parsed = client.parse_event(event)

        assert parsed["host"] == "1.2.3.4"
        assert parsed["port"] == 9200
        assert parsed["source"] == "binaryedge"
        assert parsed["country"] == "US"
        assert parsed["cluster_name"] == "test-cluster"
        assert parsed["number_nodes"] == 3
        assert parsed["cluster_size_bytes"] == 1024000
        assert len(parsed["indices"]) == 1  # Only the one with size > 1
        assert parsed["indices"][0]["name"] == "test-index"

    def test_parse_event_empty(self):
        """Test parsing an event with minimal data."""
        client = BinaryEdgeClient("test_api_key")

        event = {}

        parsed = client.parse_event(event)

        assert parsed["host"] == ""
        assert parsed["port"] == 9200
        assert parsed["source"] == "binaryedge"
        assert parsed["country"] == ""
        assert parsed["cluster_name"] == ""
        assert parsed["number_nodes"] == 0
        assert parsed["cluster_size_bytes"] == 0
        assert parsed["indices"] == []

    def test_parse_event_no_indices(self):
        """Test parsing an event with no indices."""
        client = BinaryEdgeClient("test_api_key")

        event = {
            "target": {"ip": "1.2.3.4", "port": 9200},
            "origin": {"country": "FR"},
            "result": {
                "data": {
                    "cluster_name": "empty-cluster",
                    "cluster_nodes": 1,
                }
            },
        }

        parsed = client.parse_event(event)

        assert parsed["host"] == "1.2.3.4"
        assert parsed["cluster_name"] == "empty-cluster"
        assert parsed["indices"] == []
        assert parsed["cluster_size_bytes"] == 0
