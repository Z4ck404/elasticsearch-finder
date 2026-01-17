"""Command-line interface for Elasticsearch Finder."""

import argparse
import json
import sys
from datetime import datetime

from colorama import Fore, Style
from termcolor import colored

from . import __version__
from .analyzers import CloudProviderAnalyzer, ElasticsearchScanner, PIIScanner, RiskScorer
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
    parser.add_argument(
        "--analyze",
        action="store_true",
        dest="analyze",
        help="Enable deep analysis (cloud provider detection, PII scanning, risk scoring)",
    )
    parser.add_argument(
        "--deep-scan",
        action="store_true",
        dest="deep_scan",
        help="Perform deep scan on found instances (queries ES directly - use responsibly)",
    )
    parser.add_argument(
        "--provider",
        dest="provider",
        help="Filter by cloud provider (aws, gcp, azure, ovh, digitalocean, etc.)",
        required=False,
    )
    parser.add_argument(
        "--min-risk",
        dest="min_risk",
        choices=["informational", "low", "medium", "high", "critical"],
        help="Minimum risk level to report",
        required=False,
    )
    parser.add_argument(
        "--pii-only",
        action="store_true",
        dest="pii_only",
        help="Only show results with detected PII",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results in JSON format",
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


# Initialize analyzers globally for reuse
cloud_analyzer = CloudProviderAnalyzer()
pii_scanner = PIIScanner()
risk_scorer = RiskScorer()
es_scanner = ElasticsearchScanner()


def analyze_result(parsed, args):
    """Perform deep analysis on a parsed result.

    Args:
        parsed: Parsed result dict.
        args: Command line arguments.

    Returns:
        Enhanced result dict with analysis.
    """
    analysis = {
        "cloud_provider": None,
        "pii_analysis": None,
        "index_analysis": None,
        "risk_score": None,
        "direct_scan": None,
    }

    # Cloud provider detection
    cloud_result = cloud_analyzer.analyze(
        ip=parsed.get("host"),
        org=parsed.get("organization"),
        hostname=parsed.get("hostname"),
        asn=parsed.get("asn"),
        isp=parsed.get("isp"),
    )
    analysis["cloud_provider"] = cloud_result

    # Index analysis
    indices = parsed.get("indices", [])
    if indices:
        if isinstance(indices, str):
            # Parse string indices if needed
            index_names = [i.strip() for i in indices.split(",") if i.strip()]
        else:
            index_names = indices
        analysis["index_analysis"] = pii_scanner.analyze_indices(index_names)

    # Quick PII keyword scan on data
    data = parsed.get("data", "")
    if data:
        analysis["pii_analysis"] = pii_scanner.quick_scan_for_pii_keywords(data)

    # Deep scan if requested
    if args.deep_scan:
        host = parsed.get("host")
        port = parsed.get("port", 9200)
        if host:
            print(f"  {Fore.YELLOW}[*] Performing deep scan on {host}:{port}...{Style.RESET_ALL}")
            analysis["direct_scan"] = es_scanner.full_scan(host, port, deep_scan=True)

            # Enhanced PII scan on sampled documents
            if analysis["direct_scan"].get("document_samples"):
                all_docs_text = json.dumps(analysis["direct_scan"]["document_samples"])
                analysis["pii_analysis"] = pii_scanner.scan_text(all_docs_text)

    # Risk scoring
    analysis["risk_score"] = risk_scorer.calculate_risk_score(
        cluster_size_bytes=parsed.get("cluster_size_bytes", 0),
        index_analysis=analysis.get("index_analysis"),
        pii_analysis=analysis.get("pii_analysis"),
        cloud_analysis=analysis.get("cloud_provider"),
        node_count=parsed.get("number_nodes", 0),
        is_accessible=True,
    )

    return analysis


def should_include_result(parsed, analysis, args):
    """Check if result should be included based on filters.

    Args:
        parsed: Parsed result dict.
        analysis: Analysis result dict.
        args: Command line arguments.

    Returns:
        Boolean indicating if result should be included.
    """
    # Provider filter
    if args.provider:
        provider = analysis.get("cloud_provider", {}).get("provider")
        if provider != args.provider.lower():
            return False

    # Minimum risk filter
    if args.min_risk:
        risk_order = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        result_risk = analysis.get("risk_score", {}).get("risk_level", "informational")
        if risk_order.get(result_risk, 0) < risk_order.get(args.min_risk, 0):
            return False

    # PII only filter
    if args.pii_only:
        pii_analysis = analysis.get("pii_analysis", {})
        index_analysis = analysis.get("index_analysis", {})
        has_pii = (
            pii_analysis.get("found", False)
            or pii_analysis.get("likely_contains_pii", False)
            or index_analysis.get("has_critical", False)
        )
        if not has_pii:
            return False

    return True


def print_analysis(analysis):
    """Print analysis results to console.

    Args:
        analysis: Analysis result dict.
    """
    # Cloud provider
    cloud = analysis.get("cloud_provider", {})
    if cloud.get("is_cloud"):
        provider = cloud.get("provider", "unknown")
        provider_info = cloud_analyzer.get_provider_info(provider)
        print(f"  {Fore.CYAN}☁ Cloud Provider: {provider.upper()}{Style.RESET_ALL}")
        if provider_info.get("abuse_contact"):
            print(f"    Abuse Contact: {provider_info['abuse_contact']}")

    # Index sensitivity
    index_analysis = analysis.get("index_analysis", {})
    if index_analysis.get("has_critical"):
        print(f"  {Fore.RED}⚠ CRITICAL: Sensitive indices detected!{Style.RESET_ALL}")
        for idx in index_analysis.get("critical_indices", [])[:3]:
            print(f"    - {idx}")

    # PII detection
    pii = analysis.get("pii_analysis", {})
    if pii.get("found") or pii.get("likely_contains_pii"):
        print(f"  {Fore.RED}🔓 PII DETECTED:{Style.RESET_ALL}")
        if pii.get("findings"):
            for finding in pii.get("findings", [])[:5]:
                severity_color = Fore.RED if finding["severity"] == "critical" else Fore.YELLOW
                print(
                    f"    {severity_color}• {finding['description']}: {finding['count']} instances{Style.RESET_ALL}"
                )
        elif pii.get("matched_keywords"):
            print(f"    Keywords: {', '.join(pii['matched_keywords'][:5])}")

    # Risk score
    risk = analysis.get("risk_score", {})
    if risk:
        level = risk.get("risk_level", "unknown")
        color_map = {
            "critical": Fore.RED,
            "high": Fore.YELLOW,
            "medium": Fore.CYAN,
            "low": Fore.GREEN,
            "informational": Fore.WHITE,
        }
        color = color_map.get(level, Fore.WHITE)
        bar = risk_scorer.format_score_display(risk)
        print(f"  {color}📊 Risk Score: {bar}{Style.RESET_ALL}")

        # Recommendations
        for rec in risk.get("recommendations", [])[:2]:
            print(f"    → {rec['action']}")


def process_shodan_results(
    client, country, text_exporter, excel_exporter, first_page, last_page, args
):
    """Process results from Shodan.

    Args:
        client: ShodanClient instance.
        country: Optional country code filter.
        text_exporter: TextExporter instance.
        excel_exporter: ExcelExporter instance.
        first_page: First page to process.
        last_page: Last page to process.
        args: Command line arguments.
    """
    excel_exporter.create_worksheet("shodan")
    results_json = []

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
            parsed["indices"] = indices_str

            # Perform analysis if enabled
            analysis = None
            if args.analyze or args.deep_scan or args.provider or args.min_risk or args.pii_only:
                analysis = analyze_result(parsed, args)

                # Check filters
                if not should_include_result(parsed, analysis, args):
                    continue

            # Print result info
            print(colored(f"\n[+] INFO: Found {parsed['host']}", "green"))
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

            # Print analysis if available
            if analysis:
                print_analysis(analysis)
                parsed["analysis"] = analysis

            print("-----------------------------")

            # Store for JSON output
            if args.json_output:
                results_json.append(parsed)

            # Write to exporters
            text_exporter.write_result(parsed)
            excel_exporter.write_result("shodan", parsed)

    return results_json


def process_binaryedge_results(
    client, country, text_exporter, excel_exporter, first_page, last_page, args
):
    """Process results from BinaryEdge.

    Args:
        client: BinaryEdgeClient instance.
        country: Optional country code filter.
        text_exporter: TextExporter instance.
        excel_exporter: ExcelExporter instance.
        first_page: First page to process.
        last_page: Last page to process.
        args: Command line arguments.
    """
    excel_exporter.create_worksheet("binaryedge")
    results_json = []

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

            # Perform analysis if enabled
            analysis = None
            if args.analyze or args.deep_scan or args.provider or args.min_risk or args.pii_only:
                analysis = analyze_result(parsed, args)

                # Check filters
                if not should_include_result(parsed, analysis, args):
                    continue

            # Print result info
            print(colored(f"\n[+] INFO: Found {parsed['host']}", "green"))
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

            # Print analysis if available
            if analysis:
                print_analysis(analysis)
                parsed["analysis"] = analysis

            print("\n -----------------------------\n")

            # Store for JSON output
            if args.json_output:
                results_json.append(parsed)

            # Write to exporters only if cluster has data
            if parsed.get("cluster_size_bytes", 0) > 10:
                text_exporter.write_result(parsed)
                excel_exporter.write_result("binaryedge", parsed)

    return results_json


def print_summary(results):
    """Print a summary of all analyzed results.

    Args:
        results: List of all result dicts.
    """
    if not results:
        return

    print(colored("\n" + "=" * 60, "cyan"))
    print(colored("                    SCAN SUMMARY", "cyan"))
    print(colored("=" * 60, "cyan"))

    total = len(results)
    critical = 0
    high = 0
    with_pii = 0
    by_provider = {}

    for r in results:
        analysis = r.get("analysis", {})

        # Count risk levels
        risk_level = analysis.get("risk_score", {}).get("risk_level", "")
        if risk_level == "critical":
            critical += 1
        elif risk_level == "high":
            high += 1

        # Count PII findings
        pii = analysis.get("pii_analysis", {})
        if pii.get("found") or pii.get("likely_contains_pii"):
            with_pii += 1

        # Count by provider
        provider = analysis.get("cloud_provider", {}).get("provider")
        if provider:
            by_provider[provider] = by_provider.get(provider, 0) + 1

    print(f"\n{Fore.WHITE}Total instances found: {total}{Style.RESET_ALL}")
    print(f"{Fore.RED}Critical risk: {critical}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}High risk: {high}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}With PII detected: {with_pii}{Style.RESET_ALL}")

    if by_provider:
        print(f"\n{Fore.CYAN}By Cloud Provider:{Style.RESET_ALL}")
        for provider, count in sorted(by_provider.items(), key=lambda x: -x[1]):
            print(f"  {provider.upper()}: {count}")

    print(colored("=" * 60 + "\n", "cyan"))


def main():
    """Main entry point."""
    banner()

    args = parse_args()

    # Validate source selection
    if not args.shodan and not args.binaryedge:
        print("Please specify a data source by adding -s (Shodan) and/or -b (BinaryEdge)")
        sys.exit(1)

    # Print analysis mode info
    if args.analyze:
        print(
            colored(
                "[*] Analysis mode enabled (cloud detection, PII scanning, risk scoring)", "cyan"
            )
        )
    if args.deep_scan:
        print(
            colored(
                "[*] Deep scan enabled - will query ES instances directly (use responsibly!)",
                "yellow",
            )
        )
    if args.provider:
        print(colored(f"[*] Filtering by cloud provider: {args.provider.upper()}", "cyan"))
    if args.min_risk:
        print(colored(f"[*] Minimum risk level filter: {args.min_risk.upper()}", "cyan"))
    if args.pii_only:
        print(colored("[*] Showing only results with detected PII", "cyan"))

    # Setup output files
    output_filename = get_output_filename(args.output)
    text_exporter = TextExporter(f"{output_filename}.txt")
    all_results = []

    with ExcelExporter(output_filename) as excel_exporter:
        # Process Shodan
        if args.shodan:
            try:
                api_key = get_shodan_api_key()
                client = ShodanClient(api_key)
                results = process_shodan_results(
                    client,
                    args.country,
                    text_exporter,
                    excel_exporter,
                    args.first,
                    args.last,
                    args,
                )
                if results:
                    all_results.extend(results)
            except ValueError as e:
                print(f"Shodan error: {e}")
                if not args.binaryedge:
                    sys.exit(1)

        # Process BinaryEdge
        if args.binaryedge:
            try:
                api_key = get_binaryedge_api_key()
                client = BinaryEdgeClient(api_key)
                results = process_binaryedge_results(
                    client,
                    args.country,
                    text_exporter,
                    excel_exporter,
                    args.first,
                    args.last,
                    args,
                )
                if results:
                    all_results.extend(results)
            except ValueError as e:
                print(f"BinaryEdge error: {e}")
                if not args.shodan:
                    sys.exit(1)

    # Save JSON output if requested
    if args.json_output and all_results:
        json_filename = f"{output_filename}.json"
        with open(json_filename, "w", encoding="utf-8") as f:
            # Convert non-serializable objects
            json.dump(all_results, f, indent=2, default=str)
        print(f"\nJSON results saved to: {json_filename}")

    print(f"\nResults saved to: {output_filename}.txt and {output_filename}.xlsx")

    # Print summary
    if args.analyze or args.deep_scan:
        print_summary(all_results)


if __name__ == "__main__":
    main()
