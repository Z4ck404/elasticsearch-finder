"""Configuration management for Elasticsearch Finder."""

import os


def get_shodan_api_key():
    """Get Shodan API key from environment variable."""
    key = os.environ.get("SHODAN_API_KEY", "")
    if not key:
        raise ValueError(
            "SHODAN_API_KEY environment variable is not set. "
            "Please set it with your Shodan API key."
        )
    return key


def get_binaryedge_api_key():
    """Get BinaryEdge API key from environment variable."""
    key = os.environ.get("BINARYEDGE_API_KEY", "")
    if not key:
        raise ValueError(
            "BINARYEDGE_API_KEY environment variable is not set. "
            "Please set it with your BinaryEdge API key."
        )
    return key
