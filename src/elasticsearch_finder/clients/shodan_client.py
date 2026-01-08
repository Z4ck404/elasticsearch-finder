"""Shodan API client for Elasticsearch Finder."""

from time import sleep

import shodan


class ShodanClient:
    """Client for interacting with the Shodan API."""

    def __init__(self, api_key):
        """Initialize the Shodan client.

        Args:
            api_key: Shodan API key.
        """
        self.api = shodan.Shodan(api_key)

    def search_elasticsearch(self, country=None, page=1):
        """Search for Elasticsearch instances.

        Args:
            country: Optional country code to filter results.
            page: Page number for results.

        Returns:
            List of Elasticsearch instances from Shodan.
        """
        if country:
            query = f'port:9200 json country:"{country}"'
        else:
            query = "port:9200 json"

        try:
            results = self.api.search(query, page=page)
            sleep(1)  # Rate limiting
            return results.get("matches", [])
        except shodan.APIError as e:
            raise Exception(f"Shodan API error: {e}") from e

    def get_host_info(self, ip):
        """Get detailed host information.

        Args:
            ip: IP address to query.

        Returns:
            Dict with host information.
        """
        try:
            return self.api.host(ip)
        except shodan.APIError:
            return None

    def parse_result(self, result):
        """Parse a Shodan result into a standardized format.

        Args:
            result: Raw Shodan result dict.

        Returns:
            Parsed dict with standardized fields, or None if parsing fails.
        """
        try:
            host = str(result.get("ip_str", ""))
            elastic_data = result.get("elastic", {})
            cluster = elastic_data.get("cluster", {})

            return {
                "host": host,
                "port": 9200,
                "source": "shodan",
                "cluster_name": cluster.get("cluster_name", ""),
                "status": cluster.get("status", ""),
                "country": result.get("location", {}).get("country_code", ""),
                "number_nodes": cluster.get("nodes", {}).get("count", {}).get("total", 0),
                "organization": result.get("org", ""),
                "cluster_size_bytes": (
                    cluster.get("indices", {}).get("store", {}).get("size_in_bytes", 0)
                ),
                "data": result.get("data", ""),
            }
        except (KeyError, TypeError):
            return None
