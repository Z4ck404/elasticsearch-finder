"""Command-line interface for Elasticsearch Finder."""

import argparse
import sys
from datetime import datetime

from colorama import Fore
from termcolor import colored

from . import __version__
from .clients import BinaryEdgeClient, ShodanClient
from .config import get_binaryedge_api_key, get_shodan_api_key
from .exporters import ExcelExporter, TextExporter
from .utils import extract_elastic_indices, format_bytes


def banner():
    """Print the application banner."""
    print(
        """

            ___________       ___________   ______  __________
           / ____/ ___/      / ____/  _/ | / / __ \\/ ____/ __ \\
          / __/  \\__ \\______/ /_   / //  |/ / / / / __/ / /_/ /
         / /___ ___/ /_____/ __/ _/ // /|  / /_/ / /___/ _, _/
        /_____//____/     /_/   /___/_/ |_/_____/_____/_/ |_|

     **** Find elastic search instances available in the web ****
        """
    )

    print(colored("Author: Zakaria EL BAZI (@Z4ck404)", "magenta"))
    print(colored(f"Version {__version__}\n\n", "magenta"))


def parse_args():
    """Parse command line arguments.

    Returns:
        Parsed arguments namespace.
    """
    parser = argparse.ArgumentParser(
        description="Find open Elasticsearch instances for bug bounty",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output",
        help="Name of the output file (without extension)",
        required=False,
    )
    parser.add_argument(
        "-c",
        "--country",
        dest="country",
        help="The country code to scan (e.g., US, FR, DE)",
        required=False,
    )
    parser.add_argument(
        "-k",
        "--keyword",
        dest="keyword",
        help="Add a keyword to search (e.g., specific indice name)",
        required=False,
    )
    parser.add_argument(
        "-f",
        "--first",
        dest="first",
        help="First page to check (for pagination)",
        default=1,
        type=int,
        required=False,
    )
    parser.add_argument(
        "-l",
        "--last",
        dest="last",
        help="Last page to check (for pagination)",
        default=30,
        type=int,
        required=False,
    )
    parser.add_argument(
        "-s",
        "--shodan",
        action="store_true",
        dest="shodan",
        help="Pull data from Shodan",
    )
    parser.add_argument(
        "-b",
        "--be",
        dest="binaryedge",
        action="store_true",
        help="Pull data from BinaryEdge",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser.parse_args()


def get_output_filename(output_arg):
    """Generate output filename.

    Args:
        output_arg: Optional output filename from arguments.

    Returns:
        Output filename string.
    """
    if output_arg:
        return output_arg
    now = datetime.now()
    dt_string = now.strftime("%d%m%Y%H%M%S")
    return f"es{dt_string}"


def process_shodan_results(client, country, text_exporter, excel_exporter, first_page, last_page):
    """Process results from Shodan.

    Args:
        client: ShodanClient instance.
        country: Optional country code filter.
        text_exporter: TextExporter instance.
        excel_exporter: ExcelExporter instance.
        first_page: First page to process.
        last_page: Last page to process.
    """
    excel_exporter.create_worksheet("shodan")

    for page in range(first_page, last_page + 1):
        try:
            results = client.search_elasticsearch(country=country, page=page)
        except Exception as e:
            print(f"Error fetching Shodan results: {e}")
            break

        for result in results:
            parsed = client.parse_result(result)
            if not parsed:
                continue

            # Calculate human-readable size
            parsed["cluster_size"] = format_bytes(parsed.get("cluster_size_bytes", 0))

            # Extract indices info
            data = parsed.get("data", "")
            indices_str = extract_elastic_indices(data)

            # Print result info
            print(colored(f"[+] INFO: Found {parsed['host']}", "green"))
            print(f"Port number: {parsed['port']}")
            print(f"Source: {parsed['source']}")
            print(f"Country: {parsed['country']}")
            print(f"Cluster name: {parsed['cluster_name']}")
            print(f"Organization: {parsed['organization']}")
            status = parsed["status"]
            status_color = status if status in ["green", "yellow", "red"] else "white"
            print(f"Status: {colored(status, status_color)}")
            print(f"Cluster size: {parsed['cluster_size']}")
            print(f"Number of nodes: {parsed['number_nodes']}")
            if indices_str:
                print(indices_str)
            print("-----------------------------")

            # Write to exporters
            parsed["indices"] = indices_str
            text_exporter.write_result(parsed)
            excel_exporter.write_result("shodan", parsed)


def process_binaryedge_results(
    client, country, text_exporter, excel_exporter, first_page, last_page
):
    """Process results from BinaryEdge.

    Args:
        client: BinaryEdgeClient instance.
        country: Optional country code filter.
        text_exporter: TextExporter instance.
        excel_exporter: ExcelExporter instance.
        first_page: First page to process.
        last_page: Last page to process.
    """
    excel_exporter.create_worksheet("binaryedge")

    for page in range(first_page, last_page + 1):
        try:
            response = client.search_elasticsearch(country=country, page=page)
            total = client.get_total_results(response)
            print(f"Total results: {Fore.GREEN}{total}{Fore.RESET}")

            events = client.get_events(response)
        except Exception as e:
            print(f"Error fetching BinaryEdge results: {e}")
            break

        for event in events:
            parsed = client.parse_event(event)

            # Calculate human-readable size
            parsed["cluster_size"] = format_bytes(parsed.get("cluster_size_bytes", 0))

            # Print result info
            print(colored(f"[+] INFO: Found {parsed['host']}", "green"))
            print(f"Port number: {parsed['port']}")
            print(f"Source: {parsed['source']}")
            print(f"Country: {parsed['country']}")
            print(f"Cluster name: {parsed['cluster_name']}")
            print(f"Number of nodes: {parsed['number_nodes']}")
            print(f"Cluster size: {parsed['cluster_size']}")

            # Print indices
            print("Elastic Indices:")
            indices = parsed.get("indices", [])
            for indice in indices:
                print(f"  Name: {Fore.GREEN}{indice['name']}{Fore.RESET}")
                print(f"  Documents: {Fore.BLUE}{indice['docs']}{Fore.RESET}")
                size_str = format_bytes(indice["size_bytes"])
                print(f"  Size: {Fore.LIGHTCYAN_EX}{size_str}{Fore.RESET}")

            print("\n -----------------------------\n")

            # Write to exporters only if cluster has data
            if parsed.get("cluster_size_bytes", 0) > 10:
                text_exporter.write_result(parsed)
                excel_exporter.write_result("binaryedge", parsed)


def main():
    """Main entry point."""
    banner()

    args = parse_args()

    # Validate source selection
    if not args.shodan and not args.binaryedge:
        print("Please specify a data source by adding -s (Shodan) and/or -b (BinaryEdge)")
        sys.exit(1)

    # Setup output files
    output_filename = get_output_filename(args.output)
    text_exporter = TextExporter(f"{output_filename}.txt")

    with ExcelExporter(output_filename) as excel_exporter:
        # Process Shodan
        if args.shodan:
            try:
                api_key = get_shodan_api_key()
                client = ShodanClient(api_key)
                process_shodan_results(
                    client,
                    args.country,
                    text_exporter,
                    excel_exporter,
                    args.first,
                    args.last,
                )
            except ValueError as e:
                print(f"Shodan error: {e}")
                if not args.binaryedge:
                    sys.exit(1)

        # Process BinaryEdge
        if args.binaryedge:
            try:
                api_key = get_binaryedge_api_key()
                client = BinaryEdgeClient(api_key)
                process_binaryedge_results(
                    client,
                    args.country,
                    text_exporter,
                    excel_exporter,
                    args.first,
                    args.last,
                )
            except ValueError as e:
                print(f"BinaryEdge error: {e}")
                if not args.shodan:
                    sys.exit(1)

    print(f"\nResults saved to: {output_filename}.txt and {output_filename}.xlsx")


if __name__ == "__main__":
    main()
