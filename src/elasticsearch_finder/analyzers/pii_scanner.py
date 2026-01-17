"""PII (Personal Identifiable Information) Scanner for Elasticsearch Finder."""

import re


class PIIScanner:
    """Scan for Personal Identifiable Information in Elasticsearch data."""

    # PII Patterns with named groups
    PII_PATTERNS = {
        "email": {
            "pattern": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "severity": "high",
            "description": "Email addresses",
            "gdpr_relevant": True,
        },
        "phone_international": {
            "pattern": r"\+[1-9]\d{1,14}",
            "severity": "high",
            "description": "International phone numbers",
            "gdpr_relevant": True,
        },
        "phone_us": {
            "pattern": r"\b(?:\d{3}[-.\s]?){2}\d{4}\b",
            "severity": "high",
            "description": "US phone numbers",
            "gdpr_relevant": True,
        },
        "ssn": {
            "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
            "severity": "critical",
            "description": "US Social Security Numbers",
            "gdpr_relevant": True,
        },
        "credit_card": {
            "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
            "severity": "critical",
            "description": "Credit card numbers",
            "gdpr_relevant": True,
        },
        "ipv4": {
            "pattern": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            "severity": "medium",
            "description": "IPv4 addresses",
            "gdpr_relevant": True,
        },
        "date_of_birth": {
            "pattern": r"\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b",
            "severity": "high",
            "description": "Dates of birth (YYYY-MM-DD)",
            "gdpr_relevant": True,
        },
        "password_field": {
            "pattern": r"[\"']?(?:password|passwd|pwd|pass)[\"']?\s*[:=]\s*[\"']?[^\s,\"'}{]+[\"']?",
            "severity": "critical",
            "description": "Password fields",
            "gdpr_relevant": True,
        },
        "api_key": {
            "pattern": r"[\"']?(?:api[_-]?key|apikey|api[_-]?secret|access[_-]?token)[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_-]{20,}[\"']?",
            "severity": "critical",
            "description": "API keys and secrets",
            "gdpr_relevant": False,
        },
        "aws_access_key": {
            "pattern": r"AKIA[0-9A-Z]{16}",
            "severity": "critical",
            "description": "AWS Access Key IDs",
            "gdpr_relevant": False,
        },
        "aws_secret_key": {
            "pattern": r"[\"']?(?:aws[_-]?secret[_-]?access[_-]?key)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{40}[\"']?",
            "severity": "critical",
            "description": "AWS Secret Access Keys",
            "gdpr_relevant": False,
        },
        "private_key": {
            "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "severity": "critical",
            "description": "Private keys",
            "gdpr_relevant": False,
        },
        "jwt_token": {
            "pattern": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
            "severity": "high",
            "description": "JWT tokens",
            "gdpr_relevant": False,
        },
        "iban": {
            "pattern": r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]?){0,16}\b",
            "severity": "critical",
            "description": "International Bank Account Numbers",
            "gdpr_relevant": True,
        },
        "medical_record": {
            "pattern": r"\b(?:mrn|medical[_-]?record[_-]?(?:number|no|num)?|patient[_-]?id)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9-]+",
            "severity": "critical",
            "description": "Medical record identifiers",
            "gdpr_relevant": True,
        },
        "national_id": {
            "pattern": r"\b(?:national[_-]?id|passport[_-]?(?:number|no|num)?|driver[_-]?license)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9-]+",
            "severity": "critical",
            "description": "National ID/Passport numbers",
            "gdpr_relevant": True,
        },
        "username": {
            "pattern": r"[\"']?(?:username|user[_-]?name|login|user[_-]?id)[\"']?\s*[:=]\s*[\"']?[^\s,\"'}{]+[\"']?",
            "severity": "medium",
            "description": "Username fields",
            "gdpr_relevant": True,
        },
        "address": {
            "pattern": r"[\"']?(?:address|street|city|zip[_-]?code|postal[_-]?code)[\"']?\s*[:=]\s*[\"']?[^\n\"'}{]+[\"']?",
            "severity": "high",
            "description": "Physical address fields",
            "gdpr_relevant": True,
        },
        "hash_md5": {
            "pattern": r"\b[a-fA-F0-9]{32}\b",
            "severity": "medium",
            "description": "MD5 hashes (possibly passwords)",
            "gdpr_relevant": False,
        },
        "hash_sha256": {
            "pattern": r"\b[a-fA-F0-9]{64}\b",
            "severity": "medium",
            "description": "SHA-256 hashes",
            "gdpr_relevant": False,
        },
    }

    # Sensitive index name patterns
    SENSITIVE_INDEX_PATTERNS = {
        "user_data": {
            "patterns": [
                r"user",
                r"customer",
                r"client",
                r"member",
                r"account",
                r"profile",
                r"person",
            ],
            "severity": "high",
            "description": "User/Customer data indices",
        },
        "authentication": {
            "patterns": [
                r"auth",
                r"login",
                r"session",
                r"token",
                r"credential",
                r"password",
            ],
            "severity": "critical",
            "description": "Authentication data indices",
        },
        "financial": {
            "patterns": [
                r"payment",
                r"transaction",
                r"order",
                r"invoice",
                r"billing",
                r"bank",
                r"card",
                r"finance",
            ],
            "severity": "critical",
            "description": "Financial data indices",
        },
        "healthcare": {
            "patterns": [
                r"patient",
                r"medical",
                r"health",
                r"diagnosis",
                r"prescription",
                r"hospital",
                r"clinic",
                r"doctor",
            ],
            "severity": "critical",
            "description": "Healthcare data indices (HIPAA)",
        },
        "logs": {
            "patterns": [
                r"log",
                r"audit",
                r"event",
                r"access",
                r"activity",
            ],
            "severity": "medium",
            "description": "Log indices (may contain PII)",
        },
        "personal": {
            "patterns": [
                r"personal",
                r"private",
                r"sensitive",
                r"pii",
                r"gdpr",
            ],
            "severity": "critical",
            "description": "Personal/Sensitive data indices",
        },
        "contact": {
            "patterns": [
                r"email",
                r"contact",
                r"phone",
                r"address",
                r"newsletter",
                r"subscriber",
            ],
            "severity": "high",
            "description": "Contact information indices",
        },
    }

    def __init__(self):
        """Initialize the PII scanner."""
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns for performance."""
        self._pii_compiled = {}
        for name, info in self.PII_PATTERNS.items():
            self._pii_compiled[name] = {
                "regex": re.compile(info["pattern"], re.IGNORECASE),
                "severity": info["severity"],
                "description": info["description"],
                "gdpr_relevant": info["gdpr_relevant"],
            }

        self._index_compiled = {}
        for category, info in self.SENSITIVE_INDEX_PATTERNS.items():
            self._index_compiled[category] = {
                "patterns": [re.compile(p, re.IGNORECASE) for p in info["patterns"]],
                "severity": info["severity"],
                "description": info["description"],
            }

    def scan_text(self, text: str, max_matches_per_type: int = 5) -> dict:
        """Scan text for PII patterns.

        Args:
            text: Text content to scan.
            max_matches_per_type: Maximum matches to return per PII type.

        Returns:
            Dict with PII findings.
        """
        if not text:
            return {"found": False, "findings": [], "summary": {}}

        findings = []
        summary = {}

        for name, info in self._pii_compiled.items():
            matches = info["regex"].findall(text)
            if matches:
                # Deduplicate and limit matches
                unique_matches = list(set(matches))[:max_matches_per_type]
                total_count = len(matches)

                findings.append(
                    {
                        "type": name,
                        "severity": info["severity"],
                        "description": info["description"],
                        "gdpr_relevant": info["gdpr_relevant"],
                        "count": total_count,
                        "samples": self._sanitize_samples(unique_matches, name),
                    }
                )
                summary[name] = total_count

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings.sort(key=lambda x: severity_order.get(x["severity"], 4))

        return {
            "found": len(findings) > 0,
            "findings": findings,
            "summary": summary,
            "total_pii_count": sum(summary.values()),
            "has_critical": any(f["severity"] == "critical" for f in findings),
            "has_gdpr_data": any(f["gdpr_relevant"] for f in findings),
        }

    def _sanitize_samples(self, samples: list, pii_type: str) -> list:
        """Sanitize PII samples for safe display.

        Args:
            samples: List of matched samples.
            pii_type: Type of PII detected.

        Returns:
            Sanitized sample list.
        """
        sanitized = []
        for sample in samples:
            if pii_type in ["credit_card", "ssn", "iban"]:
                # Heavily mask financial/identity numbers
                if len(sample) > 6:
                    sanitized.append(f"{sample[:4]}{'*' * (len(sample) - 8)}{sample[-4:]}")
                else:
                    sanitized.append("*" * len(sample))
            elif pii_type in ["password_field", "api_key", "aws_secret_key", "private_key"]:
                # Don't show credentials
                sanitized.append("[REDACTED]")
            elif pii_type == "email":
                # Partially mask email
                parts = sample.split("@")
                if len(parts) == 2:
                    local = parts[0]
                    domain = parts[1]
                    if len(local) > 2:
                        sanitized.append(f"{local[0]}***{local[-1]}@{domain}")
                    else:
                        sanitized.append(f"***@{domain}")
                else:
                    sanitized.append("***@***")
            elif pii_type in ["phone_international", "phone_us"]:
                # Mask middle of phone number
                if len(sample) > 4:
                    sanitized.append(f"{sample[:3]}***{sample[-2:]}")
                else:
                    sanitized.append("***")
            else:
                # For other types, show as-is but truncated
                if len(sample) > 50:
                    sanitized.append(f"{sample[:47]}...")
                else:
                    sanitized.append(sample)

        return sanitized

    def analyze_index_name(self, index_name: str) -> dict:
        """Analyze an Elasticsearch index name for sensitivity.

        Args:
            index_name: Name of the Elasticsearch index.

        Returns:
            Dict with sensitivity analysis.
        """
        if not index_name:
            return {"sensitive": False, "categories": [], "risk_level": "unknown"}

        categories = []
        max_severity = "low"
        severity_order = {"critical": 3, "high": 2, "medium": 1, "low": 0}

        for category, info in self._index_compiled.items():
            for pattern in info["patterns"]:
                if pattern.search(index_name):
                    categories.append(
                        {
                            "category": category,
                            "severity": info["severity"],
                            "description": info["description"],
                        }
                    )
                    if severity_order.get(info["severity"], 0) > severity_order.get(
                        max_severity, 0
                    ):
                        max_severity = info["severity"]
                    break  # One match per category is enough

        return {
            "sensitive": len(categories) > 0,
            "categories": categories,
            "risk_level": max_severity if categories else "low",
            "index_name": index_name,
        }

    def analyze_indices(self, indices: list) -> dict:
        """Analyze multiple index names.

        Args:
            indices: List of index names or dicts with 'name' key.

        Returns:
            Dict with analysis of all indices.
        """
        results = []
        critical_indices = []
        high_risk_indices = []

        for index in indices:
            # Handle both string and dict formats
            if isinstance(index, dict):
                name = index.get("name", index.get("index_name", ""))
            else:
                name = str(index)

            analysis = self.analyze_index_name(name)
            if analysis["sensitive"]:
                results.append(analysis)
                if analysis["risk_level"] == "critical":
                    critical_indices.append(name)
                elif analysis["risk_level"] == "high":
                    high_risk_indices.append(name)

        return {
            "total_indices": len(indices),
            "sensitive_indices_count": len(results),
            "sensitive_indices": results,
            "critical_indices": critical_indices,
            "high_risk_indices": high_risk_indices,
            "has_critical": len(critical_indices) > 0,
        }

    def quick_scan_for_pii_keywords(self, text: str) -> dict:
        """Quick scan for PII-related keywords (faster than full scan).

        Args:
            text: Text to scan.

        Returns:
            Dict with keyword matches.
        """
        keywords = [
            "email",
            "password",
            "username",
            "phone",
            "address",
            "ssn",
            "social security",
            "credit card",
            "bank account",
            "date of birth",
            "dob",
            "passport",
            "driver license",
            "medical",
            "patient",
            "prescription",
            "diagnosis",
            "api_key",
            "secret",
            "token",
            "private key",
        ]

        text_lower = text.lower()
        found = [kw for kw in keywords if kw in text_lower]

        return {
            "likely_contains_pii": len(found) > 0,
            "matched_keywords": found,
            "keyword_count": len(found),
        }
