"""Utility functions for Elasticsearch Finder."""

from hurry.filesize import size as format_size


def format_bytes(size_in_bytes):
    """Format bytes into human-readable size.

    Args:
        size_in_bytes: Size in bytes.

    Returns:
        Human-readable size string.
    """
    return format_size(size_in_bytes)


def extract_elastic_indices(data_string):
    """Extract Elastic Indices section from data string.

    Args:
        data_string: Raw data string from API.

    Returns:
        Indices section or empty string.
    """
    marker = "Elastic Indices"
    if marker in data_string:
        return data_string[data_string.find(marker) :]
    return ""
