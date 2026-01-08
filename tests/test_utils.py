"""Tests for utility functions."""

from elasticsearch_finder.utils import extract_elastic_indices, format_bytes


class TestFormatBytes:
    """Tests for format_bytes function."""

    def test_format_bytes_small(self):
        """Test formatting small byte values."""
        assert format_bytes(100) == "100B"

    def test_format_bytes_kilobytes(self):
        """Test formatting kilobyte values."""
        result = format_bytes(1024)
        assert "K" in result

    def test_format_bytes_megabytes(self):
        """Test formatting megabyte values."""
        result = format_bytes(1024 * 1024)
        assert "M" in result

    def test_format_bytes_gigabytes(self):
        """Test formatting gigabyte values."""
        result = format_bytes(1024 * 1024 * 1024)
        assert "G" in result

    def test_format_bytes_zero(self):
        """Test formatting zero bytes."""
        assert format_bytes(0) == "0B"


class TestExtractElasticIndices:
    """Tests for extract_elastic_indices function."""

    def test_extract_with_indices(self):
        """Test extracting indices section."""
        data = "Some data here\nElastic Indices:\n- index1\n- index2"
        result = extract_elastic_indices(data)
        assert "Elastic Indices" in result
        assert "index1" in result
        assert "index2" in result

    def test_extract_without_indices(self):
        """Test when no indices marker present."""
        data = "Some data without indices"
        result = extract_elastic_indices(data)
        assert result == ""

    def test_extract_empty_string(self):
        """Test with empty string."""
        result = extract_elastic_indices("")
        assert result == ""

    def test_extract_indices_at_start(self):
        """Test when indices marker is at start."""
        data = "Elastic Indices: test-index"
        result = extract_elastic_indices(data)
        assert result == data
