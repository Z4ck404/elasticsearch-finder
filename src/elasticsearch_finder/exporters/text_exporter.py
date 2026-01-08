"""Text file exporter for Elasticsearch Finder."""


class TextExporter:
    """Export results to a text file."""

    def __init__(self, filename):
        """Initialize the text exporter.

        Args:
            filename: Path to the output file.
        """
        self.filename = filename

    def write(self, entries):
        """Write entries to the text file.

        Args:
            entries: List of strings to write.
        """
        with open(self.filename, "a", encoding="utf-8") as f:
            f.writelines(entries)

    def write_result(self, result):
        """Write a parsed result to the text file.

        Args:
            result: Dict with result data.
        """
        entries = [
            f"host: {result.get('host', '')}\n",
            f"Port number: {result.get('port', '')}\n",
            f"source: {result.get('source', '')}\n",
            f"cluster name: {result.get('cluster_name', '')}\n",
            f"organization: {result.get('organization', '')}\n",
            f"number of nodes: {result.get('number_nodes', '')}\n",
            f"size of the cluster: {result.get('cluster_size', '')}\n",
        ]

        if result.get("indices"):
            entries.append(f"indices: {result.get('indices')}\n")

        entries.append(" \n ----------------------------- \n")
        self.write(entries)
