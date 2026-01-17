"""Direct Elasticsearch scanner for Elasticsearch Finder."""

import json

import requests
from requests.exceptions import RequestException


class ElasticsearchScanner:
    """Direct scanner for open Elasticsearch instances."""

    # Common sensitive index patterns to search
    SENSITIVE_INDEX_SAMPLES = [
        "user*",
        "customer*",
        "account*",
        "auth*",
        "login*",
        "session*",
        "payment*",
        "order*",
        "transaction*",
        "email*",
        "contact*",
        "personal*",
        "private*",
        "patient*",
        "medical*",
        "password*",
        "credential*",
    ]

    def __init__(self, timeout: int = 10):
        """Initialize the Elasticsearch scanner.

        Args:
            timeout: Request timeout in seconds.
        """
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "elasticsearch-finder/2.0 (security-research)",
                "Accept": "application/json",
            }
        )

    def check_accessibility(self, host: str, port: int = 9200) -> dict:
        """Check if Elasticsearch instance is accessible.

        Args:
            host: IP address or hostname.
            port: Port number.

        Returns:
            Dict with accessibility info.
        """
        url = f"http://{host}:{port}"
        result = {
            "accessible": False,
            "url": url,
            "version": None,
            "cluster_name": None,
            "requires_auth": False,
            "error": None,
        }

        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)

            if response.status_code == 200:
                result["accessible"] = True
                data = response.json()
                result["version"] = data.get("version", {}).get("number")
                result["cluster_name"] = data.get("cluster_name")
                result["tagline"] = data.get("tagline")
            elif response.status_code == 401:
                result["requires_auth"] = True
                result["error"] = "Authentication required"
            else:
                result["error"] = f"HTTP {response.status_code}"

        except json.JSONDecodeError:
            result["error"] = "Invalid JSON response"
        except RequestException as e:
            result["error"] = str(e)

        return result

    def get_cluster_health(self, host: str, port: int = 9200) -> dict:
        """Get cluster health information.

        Args:
            host: IP address or hostname.
            port: Port number.

        Returns:
            Dict with cluster health.
        """
        url = f"http://{host}:{port}/_cluster/health"

        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                return response.json()
        except (RequestException, json.JSONDecodeError):
            pass

        return {}

    def get_cluster_stats(self, host: str, port: int = 9200) -> dict:
        """Get cluster statistics.

        Args:
            host: IP address or hostname.
            port: Port number.

        Returns:
            Dict with cluster stats.
        """
        url = f"http://{host}:{port}/_cluster/stats"

        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                return response.json()
        except (RequestException, json.JSONDecodeError):
            pass

        return {}

    def list_indices(self, host: str, port: int = 9200) -> list:
        """List all indices in the cluster.

        Args:
            host: IP address or hostname.
            port: Port number.

        Returns:
            List of index information dicts.
        """
        url = f"http://{host}:{port}/_cat/indices?format=json"

        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                return response.json()
        except (RequestException, json.JSONDecodeError):
            pass

        return []

    def get_index_mapping(self, host: str, port: int = 9200, index: str = "_all") -> dict:
        """Get index mappings (field structure).

        Args:
            host: IP address or hostname.
            port: Port number.
            index: Index name or pattern.

        Returns:
            Dict with index mappings.
        """
        url = f"http://{host}:{port}/{index}/_mapping"

        try:
            response = self.session.get(url, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                return response.json()
        except (RequestException, json.JSONDecodeError):
            pass

        return {}

    def sample_documents(
        self,
        host: str,
        port: int = 9200,
        index: str = "_all",
        size: int = 5,
    ) -> dict:
        """Sample documents from an index (for PII scanning).

        Args:
            host: IP address or hostname.
            port: Port number.
            index: Index name or pattern.
            size: Number of documents to sample.

        Returns:
            Dict with sample documents.
        """
        url = f"http://{host}:{port}/{index}/_search"
        params = {"size": min(size, 10)}  # Limit to 10 for ethical reasons

        try:
            response = self.session.get(url, params=params, timeout=self.timeout, verify=False)
            if response.status_code == 200:
                data = response.json()
                hits = data.get("hits", {})
                return {
                    "total": hits.get("total", {}).get("value", 0)
                    if isinstance(hits.get("total"), dict)
                    else hits.get("total", 0),
                    "documents": [hit.get("_source", {}) for hit in hits.get("hits", [])],
                    "index": index,
                }
        except (RequestException, json.JSONDecodeError):
            pass

        return {"total": 0, "documents": [], "index": index}

    def analyze_field_names(self, mappings: dict) -> dict:
        """Analyze field names for sensitive data indicators.

        Args:
            mappings: Index mappings dict.

        Returns:
            Dict with sensitive field analysis.
        """
        sensitive_patterns = {
            "pii": [
                "email",
                "mail",
                "phone",
                "mobile",
                "address",
                "street",
                "city",
                "zip",
                "postal",
                "ssn",
                "social_security",
                "passport",
                "driver_license",
                "dob",
                "birth",
                "age",
                "gender",
                "sex",
                "name",
                "first_name",
                "last_name",
                "full_name",
                "username",
            ],
            "financial": [
                "credit_card",
                "card_number",
                "cvv",
                "expiry",
                "bank",
                "account_number",
                "routing",
                "iban",
                "swift",
                "payment",
                "balance",
                "salary",
                "income",
                "transaction",
            ],
            "authentication": [
                "password",
                "passwd",
                "pwd",
                "hash",
                "salt",
                "secret",
                "token",
                "api_key",
                "apikey",
                "access_token",
                "refresh_token",
                "session",
                "auth",
                "credential",
                "private_key",
            ],
            "medical": [
                "patient",
                "diagnosis",
                "prescription",
                "medication",
                "treatment",
                "doctor",
                "medical",
                "health",
                "insurance",
                "condition",
                "symptom",
                "allergy",
            ],
        }

        findings = {category: [] for category in sensitive_patterns}
        all_fields = set()

        # Extract all field names from mappings
        def extract_fields(obj, prefix=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    full_key = f"{prefix}.{key}" if prefix else key
                    all_fields.add(full_key.lower())
                    if key == "properties" and isinstance(value, dict):
                        extract_fields(value, prefix)
                    elif isinstance(value, dict):
                        extract_fields(value, full_key)

        extract_fields(mappings)

        # Check for sensitive patterns
        for field in all_fields:
            for category, patterns in sensitive_patterns.items():
                for pattern in patterns:
                    if pattern in field:
                        findings[category].append(field)
                        break

        # Calculate summary
        total_sensitive = sum(len(fields) for fields in findings.values())

        return {
            "total_fields": len(all_fields),
            "sensitive_fields_count": total_sensitive,
            "findings": findings,
            "has_pii_fields": len(findings["pii"]) > 0,
            "has_financial_fields": len(findings["financial"]) > 0,
            "has_auth_fields": len(findings["authentication"]) > 0,
            "has_medical_fields": len(findings["medical"]) > 0,
        }

    def full_scan(self, host: str, port: int = 9200, deep_scan: bool = False) -> dict:
        """Perform a full scan of an Elasticsearch instance.

        Args:
            host: IP address or hostname.
            port: Port number.
            deep_scan: Whether to sample documents (more intrusive).

        Returns:
            Comprehensive scan results.
        """
        result = {
            "host": host,
            "port": port,
            "scan_type": "deep" if deep_scan else "basic",
            "accessibility": None,
            "cluster_health": None,
            "cluster_stats": None,
            "indices": [],
            "field_analysis": None,
            "document_samples": None,
            "risk_indicators": [],
        }

        # Check accessibility first
        result["accessibility"] = self.check_accessibility(host, port)

        if not result["accessibility"]["accessible"]:
            return result

        # Get cluster info
        result["cluster_health"] = self.get_cluster_health(host, port)
        result["cluster_stats"] = self.get_cluster_stats(host, port)

        # List indices
        indices = self.list_indices(host, port)
        result["indices"] = indices

        # Risk indicators
        if len(indices) > 0:
            result["risk_indicators"].append("Indices are publicly listable")

        # Get mappings for field analysis
        mappings = self.get_index_mapping(host, port)
        if mappings:
            result["field_analysis"] = self.analyze_field_names(mappings)

            if result["field_analysis"]["has_pii_fields"]:
                result["risk_indicators"].append("PII-related fields detected in schema")
            if result["field_analysis"]["has_financial_fields"]:
                result["risk_indicators"].append("Financial data fields detected")
            if result["field_analysis"]["has_auth_fields"]:
                result["risk_indicators"].append("Authentication/credential fields detected")
            if result["field_analysis"]["has_medical_fields"]:
                result["risk_indicators"].append("Medical/health data fields detected")

        # Deep scan - sample documents
        if deep_scan:
            samples = []
            # Only sample from non-system indices
            for idx in indices[:5]:  # Limit to 5 indices
                idx_name = idx.get("index", "")
                if not idx_name.startswith("."):  # Skip system indices
                    sample = self.sample_documents(host, port, idx_name, size=3)
                    if sample["documents"]:
                        samples.append(sample)

            result["document_samples"] = samples

            if samples:
                result["risk_indicators"].append("Document data is publicly readable")

        return result

    def quick_check(self, host: str, port: int = 9200) -> dict:
        """Quick check for common vulnerabilities.

        Args:
            host: IP address or hostname.
            port: Port number.

        Returns:
            Quick vulnerability assessment.
        """
        vulnerabilities = []

        # Check if accessible without auth
        access = self.check_accessibility(host, port)
        if access["accessible"]:
            vulnerabilities.append(
                {
                    "type": "no_authentication",
                    "severity": "critical",
                    "description": "Elasticsearch accessible without authentication",
                }
            )

            # Check for old/vulnerable versions
            version = access.get("version", "")
            if version:
                major_version = int(version.split(".")[0]) if version else 0
                if major_version < 7:
                    vulnerabilities.append(
                        {
                            "type": "outdated_version",
                            "severity": "high",
                            "description": f"Running outdated version {version}",
                        }
                    )

        # Check if _all endpoint is accessible
        indices = self.list_indices(host, port)
        if indices:
            vulnerabilities.append(
                {
                    "type": "indices_listable",
                    "severity": "high",
                    "description": f"All indices ({len(indices)}) are publicly listable",
                }
            )

            # Check for sensitive-looking indices
            sensitive = [
                i
                for i in indices
                if any(
                    pat in i.get("index", "").lower()
                    for pat in ["user", "customer", "auth", "password", "payment", "medical"]
                )
            ]
            if sensitive:
                vulnerabilities.append(
                    {
                        "type": "sensitive_indices",
                        "severity": "critical",
                        "description": f"Sensitive indices detected: {[i['index'] for i in sensitive[:3]]}",
                    }
                )

        return {
            "host": host,
            "port": port,
            "vulnerable": len(vulnerabilities) > 0,
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "accessible": access["accessible"],
            "requires_auth": access.get("requires_auth", False),
        }
