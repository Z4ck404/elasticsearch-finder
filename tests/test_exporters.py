"""Tests for the exporters."""

import os
import tempfile

from elasticsearch_finder.exporters.excel_exporter import ExcelExporter
from elasticsearch_finder.exporters.text_exporter import TextExporter


class TestTextExporter:
    """Tests for TextExporter."""

    def test_init(self):
        """Test exporter initialization."""
        exporter = TextExporter("test.txt")
        assert exporter.filename == "test.txt"

    def test_write(self):
        """Test writing entries to file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test_output.txt")
            exporter = TextExporter(filepath)

            exporter.write(["line 1\n", "line 2\n"])
            exporter.write(["line 3\n"])

            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()

            assert "line 1" in content
            assert "line 2" in content
            assert "line 3" in content

    def test_write_result(self):
        """Test writing a parsed result."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test_result.txt")
            exporter = TextExporter(filepath)

            result = {
                "host": "1.2.3.4",
                "port": 9200,
                "source": "shodan",
                "cluster_name": "test-cluster",
                "organization": "Test Org",
                "number_nodes": 3,
                "cluster_size": "10K",
                "indices": ["index1", "index2"],
            }

            exporter.write_result(result)

            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()

            assert "host: 1.2.3.4" in content
            assert "Port number: 9200" in content
            assert "source: shodan" in content
            assert "cluster name: test-cluster" in content
            assert "organization: Test Org" in content
            assert "number of nodes: 3" in content


class TestExcelExporter:
    """Tests for ExcelExporter."""

    def test_init(self):
        """Test exporter initialization."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test")
            exporter = ExcelExporter(filepath)
            assert exporter.filename == f"{filepath}.xlsx"
            assert exporter.worksheets == {}
            exporter.close()

    def test_create_worksheet(self):
        """Test worksheet creation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test")
            exporter = ExcelExporter(filepath)

            worksheet = exporter.create_worksheet("test_sheet")

            assert worksheet is not None
            assert "test_sheet" in exporter.worksheets
            assert exporter.worksheets["test_sheet"]["row"] == 1

            exporter.close()

    def test_write_result(self):
        """Test writing a result to worksheet."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test")
            exporter = ExcelExporter(filepath)

            result = {
                "host": "1.2.3.4",
                "port": 9200,
                "source": "shodan",
                "country": "US",
                "cluster_name": "test-cluster",
                "hoster": "AWS",
                "organization": "Test Org",
                "number_nodes": 3,
                "cluster_size": "10K",
                "indices": ["index1"],
            }

            exporter.write_result("shodan", result)

            assert "shodan" in exporter.worksheets
            assert exporter.worksheets["shodan"]["row"] == 2  # After writing one row

            exporter.close()

            # Verify file was created
            assert os.path.exists(f"{filepath}.xlsx")

    def test_context_manager(self):
        """Test using exporter as context manager."""
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, "test")

            with ExcelExporter(filepath) as exporter:
                exporter.create_worksheet("test_sheet")
                exporter.write_result(
                    "test_sheet",
                    {"host": "1.2.3.4", "port": 9200},
                )

            # File should exist after context manager exits
            assert os.path.exists(f"{filepath}.xlsx")
