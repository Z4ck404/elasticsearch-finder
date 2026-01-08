"""Excel exporter for Elasticsearch Finder."""

import xlsxwriter


class ExcelExporter:
    """Export results to an Excel file."""

    HEADERS = [
        ("A1", "Host IP"),
        ("B1", "Port number"),
        ("C1", "Source"),
        ("D1", "Country"),
        ("E1", "Cluster name"),
        ("F1", "Hosting provider"),
        ("G1", "Organization"),
        ("H1", "Number of nodes"),
        ("I1", "Cluster size"),
        ("J1", "Indices"),
    ]

    def __init__(self, filename):
        """Initialize the Excel exporter.

        Args:
            filename: Path to the output file (without extension).
        """
        self.filename = f"{filename}.xlsx"
        self.workbook = xlsxwriter.Workbook(self.filename)
        self.worksheets = {}

    def create_worksheet(self, name):
        """Create a worksheet with headers.

        Args:
            name: Name of the worksheet.

        Returns:
            Worksheet object.
        """
        worksheet = self.workbook.add_worksheet(name)
        bold = self.workbook.add_format({"bold": True})
        worksheet.set_column(1, 1, 15)

        for cell, header in self.HEADERS:
            worksheet.write(cell, header, bold)

        self.worksheets[name] = {"sheet": worksheet, "row": 1}
        return worksheet

    def write_result(self, worksheet_name, result):
        """Write a result to the specified worksheet.

        Args:
            worksheet_name: Name of the worksheet.
            result: Dict with result data.
        """
        if worksheet_name not in self.worksheets:
            self.create_worksheet(worksheet_name)

        ws_data = self.worksheets[worksheet_name]
        worksheet = ws_data["sheet"]
        row = ws_data["row"]

        worksheet.write(row, 0, result.get("host", ""))
        worksheet.write(row, 1, result.get("port", ""))
        worksheet.write(row, 2, result.get("source", ""))
        worksheet.write(row, 3, result.get("country", ""))
        worksheet.write(row, 4, result.get("cluster_name", ""))
        worksheet.write(row, 5, result.get("hoster", ""))
        worksheet.write(row, 6, str(result.get("organization", "")))
        worksheet.write(row, 7, result.get("number_nodes", 0))
        worksheet.write(row, 8, str(result.get("cluster_size", "")))
        worksheet.write(row, 9, str(result.get("indices", [])))

        ws_data["row"] = row + 1

    def close(self):
        """Close the workbook."""
        self.workbook.close()

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()
        return False
