"""BinaryEdge API client for Elasticsearch Finder."""

import requests


class BinaryEdgeClient:
    """Client for interacting with the BinaryEdge API."""

    BASE_URL = "https://api.binaryedge.io/v2/query/search"

    def __init__(self, api_key):
        """Initialize the BinaryEdge client.

        Args:
            api_key: BinaryEdge API key.
        """
        self.api_key = api_key
        self.headers = {"X-Key": api_key}

    def search_elasticsearch(self, country=None, page=1):
        """Search for Elasticsearch instances.

        Args:
            country: Optional country code to filter results.
            page: Page number for results.

        Returns:
            Dict with search results.
        """
        if country:
            query = f'type:"elasticsearch" country:"{country}"'
        else:
            query = 'type:"elasticsearch"'

        params = {"query": query, "page": page}

        try:
            response = requests.get(self.BASE_URL, headers=self.headers, params=params, timeout=15)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            raise Exception(f"BinaryEdge API error: {e}") from e

    def get_total_results(self, response):
        """Get total number of results from response.

        Args:
            response: API response dict.

        Returns:
            Total count of results.
        """
        return response.get("total", 0)

    def get_events(self, response):
        """Get events from response.

        Args:
            response: API response dict.

        Returns:
            List of events.
        """
        return response.get("events", [])

    def parse_event(self, event):
        """Parse a BinaryEdge event into a standardized format.

        Args:
            event: Raw event dict from BinaryEdge.

        Returns:
            Parsed dict with standardized fields.
        """
        target = event.get("target", {})
        origin = event.get("origin", {})
        result_data = event.get("result", {}).get("data", {})

        indices = []
        total_size = 0

        for indice in result_data.get("indices", []):
            size_bytes = indice.get("size_in_bytes", 0)
            if size_bytes > 1:
                indices.append(
                    {
                        "name": indice.get("index_name", ""),
                        "docs": indice.get("docs", 0),
                        "size_bytes": size_bytes,
                    }
                )
            total_size += size_bytes

        return {
            "host": target.get("ip", ""),
            "port": target.get("port", 9200),
            "source": "binaryedge",
            "country": origin.get("country", ""),
            "cluster_name": result_data.get("cluster_name", ""),
            "number_nodes": result_data.get("cluster_nodes", 0),
            "cluster_size_bytes": total_size,
            "indices": indices,
        }
