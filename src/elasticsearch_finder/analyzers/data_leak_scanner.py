"""Advanced Data Leak Scanner for Elasticsearch Finder.

This module provides comprehensive data leak detection capabilities for
exposed Elasticsearch instances, including personal data detection,
credential scanning, and compliance risk assessment.
"""

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class DataCategory(Enum):
    """Categories of sensitive data."""

    PERSONAL = "personal"
    FINANCIAL = "financial"
    HEALTHCARE = "healthcare"
    AUTHENTICATION = "authentication"
    CORPORATE = "corporate"
    GOVERNMENT = "government"
    BEHAVIORAL = "behavioral"


class ComplianceFramework(Enum):
    """Compliance frameworks for data protection."""

    GDPR = "gdpr"
    CCPA = "ccpa"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    SOX = "sox"
    FERPA = "ferpa"


@dataclass
class DataLeakFinding:
    """Represents a data leak finding."""

    category: DataCategory
    data_type: str
    severity: str  # critical, high, medium, low
    count: int
    samples: List[str] = field(default_factory=list)
    compliance_impact: List[ComplianceFramework] = field(default_factory=list)
    description: str = ""
    field_names: List[str] = field(default_factory=list)


class DataLeakScanner:
    """Advanced scanner for detecting leaked personal and sensitive data."""

    # Extended email patterns for various formats
    EMAIL_PATTERNS = {
        "standard_email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
        "corporate_email": r"[a-zA-Z0-9._%+-]+@(?:gmail|yahoo|outlook|hotmail|protonmail|icloud|mail)\.[a-zA-Z]{2,}",
        "disposable_email": r"[a-zA-Z0-9._%+-]+@(?:tempmail|guerrillamail|10minutemail|throwaway|mailinator)\.[a-zA-Z]{2,}",
    }

    # Comprehensive PII patterns by country/region
    REGIONAL_PII_PATTERNS = {
        # US patterns
        "us_ssn": {
            "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
            "description": "US Social Security Number",
            "category": DataCategory.PERSONAL,
            "severity": "critical",
            "compliance": [ComplianceFramework.CCPA],
        },
        "us_phone": {
            "pattern": r"\b(?:\+1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b",
            "description": "US Phone Number",
            "category": DataCategory.PERSONAL,
            "severity": "high",
            "compliance": [ComplianceFramework.CCPA],
        },
        "us_driver_license": {
            "pattern": r"\b(?:DL|D\.L\.|Driver['\s]?s?['\s]?License)[:\s]?[A-Z0-9]{5,15}\b",
            "description": "US Driver's License",
            "category": DataCategory.GOVERNMENT,
            "severity": "critical",
            "compliance": [ComplianceFramework.CCPA],
        },
        # EU patterns
        "eu_iban": {
            "pattern": r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]?){0,16}\b",
            "description": "EU IBAN",
            "category": DataCategory.FINANCIAL,
            "severity": "critical",
            "compliance": [ComplianceFramework.GDPR, ComplianceFramework.PCI_DSS],
        },
        "eu_vat": {
            "pattern": r"\b[A-Z]{2}[0-9A-Z]{2,12}\b",
            "description": "EU VAT Number",
            "category": DataCategory.CORPORATE,
            "severity": "medium",
            "compliance": [ComplianceFramework.GDPR],
        },
        # UK patterns
        "uk_nino": {
            "pattern": r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b",
            "description": "UK National Insurance Number",
            "category": DataCategory.GOVERNMENT,
            "severity": "critical",
            "compliance": [ComplianceFramework.GDPR],
        },
        "uk_postcode": {
            "pattern": r"\b[A-Z]{1,2}[0-9][0-9A-Z]?\s?[0-9][A-Z]{2}\b",
            "description": "UK Postal Code",
            "category": DataCategory.PERSONAL,
            "severity": "medium",
            "compliance": [ComplianceFramework.GDPR],
        },
        # French patterns
        "fr_insee": {
            "pattern": r"\b[12]\d{2}(?:0[1-9]|1[0-2])(?:2[AB]|\d{2})\d{3}\d{3}\d{2}\b",
            "description": "French INSEE/Social Security Number",
            "category": DataCategory.GOVERNMENT,
            "severity": "critical",
            "compliance": [ComplianceFramework.GDPR],
        },
        # German patterns
        "de_tax_id": {
            "pattern": r"\b\d{2}\s?\d{3}\s?\d{5}\b",
            "description": "German Tax ID",
            "category": DataCategory.GOVERNMENT,
            "severity": "critical",
            "compliance": [ComplianceFramework.GDPR],
        },
        # Generic patterns
        "passport": {
            "pattern": r"\b(?:passport[:\s]?)?[A-Z]{1,2}\d{6,9}\b",
            "description": "Passport Number",
            "category": DataCategory.GOVERNMENT,
            "severity": "critical",
            "compliance": [ComplianceFramework.GDPR, ComplianceFramework.CCPA],
        },
        "date_of_birth": {
            "pattern": r"\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])\b",
            "description": "Date of Birth",
            "category": DataCategory.PERSONAL,
            "severity": "high",
            "compliance": [
                ComplianceFramework.GDPR,
                ComplianceFramework.CCPA,
                ComplianceFramework.HIPAA,
            ],
        },
        "ip_address": {
            "pattern": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
            "description": "IP Address",
            "category": DataCategory.BEHAVIORAL,
            "severity": "medium",
            "compliance": [ComplianceFramework.GDPR],
        },
        "mac_address": {
            "pattern": r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
            "description": "MAC Address",
            "category": DataCategory.BEHAVIORAL,
            "severity": "low",
            "compliance": [ComplianceFramework.GDPR],
        },
    }

    # Financial data patterns
    FINANCIAL_PATTERNS = {
        "credit_card_visa": {
            "pattern": r"\b4[0-9]{12}(?:[0-9]{3})?\b",
            "description": "Visa Credit Card",
            "category": DataCategory.FINANCIAL,
            "severity": "critical",
            "compliance": [ComplianceFramework.PCI_DSS],
        },
        "credit_card_mastercard": {
            "pattern": r"\b5[1-5][0-9]{14}\b",
            "description": "Mastercard Credit Card",
            "category": DataCategory.FINANCIAL,
            "severity": "critical",
            "compliance": [ComplianceFramework.PCI_DSS],
        },
        "credit_card_amex": {
            "pattern": r"\b3[47][0-9]{13}\b",
            "description": "American Express Credit Card",
            "category": DataCategory.FINANCIAL,
            "severity": "critical",
            "compliance": [ComplianceFramework.PCI_DSS],
        },
        "credit_card_discover": {
            "pattern": r"\b6(?:011|5[0-9]{2})[0-9]{12}\b",
            "description": "Discover Credit Card",
            "category": DataCategory.FINANCIAL,
            "severity": "critical",
            "compliance": [ComplianceFramework.PCI_DSS],
        },
        "bitcoin_address": {
            "pattern": r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b",
            "description": "Bitcoin Address",
            "category": DataCategory.FINANCIAL,
            "severity": "medium",
            "compliance": [],
        },
        "ethereum_address": {
            "pattern": r"\b0x[a-fA-F0-9]{40}\b",
            "description": "Ethereum Address",
            "category": DataCategory.FINANCIAL,
            "severity": "medium",
            "compliance": [],
        },
        "bank_routing": {
            "pattern": r"\b(?:routing[:\s]?)?[0-9]{9}\b",
            "description": "Bank Routing Number",
            "category": DataCategory.FINANCIAL,
            "severity": "high",
            "compliance": [ComplianceFramework.PCI_DSS, ComplianceFramework.SOX],
        },
    }

    # Authentication and credential patterns
    AUTH_PATTERNS = {
        "password_hash_md5": {
            "pattern": r"\b[a-fA-F0-9]{32}\b",
            "description": "MD5 Hash (possibly password)",
            "category": DataCategory.AUTHENTICATION,
            "severity": "high",
            "compliance": [],
        },
        "password_hash_sha256": {
            "pattern": r"\b[a-fA-F0-9]{64}\b",
            "description": "SHA-256 Hash",
            "category": DataCategory.AUTHENTICATION,
            "severity": "high",
            "compliance": [],
        },
        "password_hash_bcrypt": {
            "pattern": r"\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}",
            "description": "BCrypt Hash",
            "category": DataCategory.AUTHENTICATION,
            "severity": "high",
            "compliance": [],
        },
        "jwt_token": {
            "pattern": r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*",
            "description": "JWT Token",
            "category": DataCategory.AUTHENTICATION,
            "severity": "critical",
            "compliance": [],
        },
        "api_key_generic": {
            "pattern": r"[\"']?(?:api[_-]?key|apikey|api[_-]?secret)[\"']?\s*[:=]\s*[\"']?[a-zA-Z0-9_-]{20,}[\"']?",
            "description": "API Key",
            "category": DataCategory.AUTHENTICATION,
            "severity": "critical",
            "compliance": [],
        },
        "aws_access_key": {
            "pattern": r"AKIA[0-9A-Z]{16}",
            "description": "AWS Access Key ID",
            "category": DataCategory.AUTHENTICATION,
            "severity": "critical",
            "compliance": [],
        },
        "aws_secret_key": {
            "pattern": r"[a-zA-Z0-9/+=]{40}",
            "description": "AWS Secret Access Key (potential)",
            "category": DataCategory.AUTHENTICATION,
            "severity": "critical",
            "compliance": [],
        },
        "github_token": {
            "pattern": r"ghp_[a-zA-Z0-9]{36}",
            "description": "GitHub Personal Access Token",
            "category": DataCategory.AUTHENTICATION,
            "severity": "critical",
            "compliance": [],
        },
        "google_api_key": {
            "pattern": r"AIza[0-9A-Za-z_-]{35}",
            "description": "Google API Key",
            "category": DataCategory.AUTHENTICATION,
            "severity": "high",
            "compliance": [],
        },
        "private_key": {
            "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            "description": "Private Key",
            "category": DataCategory.AUTHENTICATION,
            "severity": "critical",
            "compliance": [],
        },
        "password_field": {
            "pattern": r"[\"']?(?:password|passwd|pwd|secret|pass)[\"']?\s*[:=]\s*[\"']?[^\s,\"'}{]+[\"']?",
            "description": "Password Field",
            "category": DataCategory.AUTHENTICATION,
            "severity": "critical",
            "compliance": [],
        },
    }

    # Healthcare/Medical patterns (HIPAA)
    HEALTHCARE_PATTERNS = {
        "medical_record_number": {
            "pattern": r"[\"']?(?:mrn|medical[_-]?record|patient[_-]?id)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9-]+[\"']?",
            "description": "Medical Record Number",
            "category": DataCategory.HEALTHCARE,
            "severity": "critical",
            "compliance": [ComplianceFramework.HIPAA],
        },
        "npi_number": {
            "pattern": r"\b\d{10}\b",
            "description": "NPI Number (potential)",
            "category": DataCategory.HEALTHCARE,
            "severity": "medium",
            "compliance": [ComplianceFramework.HIPAA],
        },
        "diagnosis_code": {
            "pattern": r"\b[A-Z]\d{2}(?:\.\d{1,4})?\b",
            "description": "ICD-10 Diagnosis Code",
            "category": DataCategory.HEALTHCARE,
            "severity": "high",
            "compliance": [ComplianceFramework.HIPAA],
        },
        "drug_name": {
            "pattern": r"(?i)\b(?:prescription|medication|drug|rx)[:\s]+[A-Za-z0-9\s-]+",
            "description": "Drug/Prescription Information",
            "category": DataCategory.HEALTHCARE,
            "severity": "high",
            "compliance": [ComplianceFramework.HIPAA],
        },
    }

    # Behavioral/Tracking patterns
    BEHAVIORAL_PATTERNS = {
        "user_agent": {
            "pattern": r"Mozilla/[0-9.]+\s*\([^)]+\)",
            "description": "User Agent String",
            "category": DataCategory.BEHAVIORAL,
            "severity": "low",
            "compliance": [ComplianceFramework.GDPR],
        },
        "session_id": {
            "pattern": r"(?:session[_-]?id|sessionid|sid)[:\s=]+[a-zA-Z0-9-]{20,}",
            "description": "Session ID",
            "category": DataCategory.BEHAVIORAL,
            "severity": "medium",
            "compliance": [ComplianceFramework.GDPR],
        },
        "tracking_id": {
            "pattern": r"(?:tracking[_-]?id|tracker[_-]?id|trace[_-]?id)[:\s=]+[a-zA-Z0-9-]+",
            "description": "Tracking/Trace ID",
            "category": DataCategory.BEHAVIORAL,
            "severity": "low",
            "compliance": [ComplianceFramework.GDPR],
        },
        "geolocation": {
            "pattern": r"(?:latitude|lat)[:\s=]+[-]?\d{1,3}\.\d+.*(?:longitude|lon|lng)[:\s=]+[-]?\d{1,3}\.\d+",
            "description": "Geolocation Coordinates",
            "category": DataCategory.BEHAVIORAL,
            "severity": "high",
            "compliance": [ComplianceFramework.GDPR, ComplianceFramework.CCPA],
        },
    }

    # Sensitive field name patterns
    SENSITIVE_FIELD_PATTERNS = {
        "personal": [
            "email",
            "mail",
            "e_mail",
            "firstname",
            "first_name",
            "lastname",
            "last_name",
            "fullname",
            "full_name",
            "name",
            "phone",
            "mobile",
            "telephone",
            "address",
            "street",
            "city",
            "state",
            "zip",
            "zipcode",
            "postal",
            "country",
            "dob",
            "birthdate",
            "birth_date",
            "birthday",
            "age",
            "gender",
            "sex",
            "nationality",
            "ethnicity",
            "race",
            "ssn",
            "social_security",
            "tax_id",
            "passport",
            "driver_license",
        ],
        "financial": [
            "credit_card",
            "creditcard",
            "card_number",
            "cardnumber",
            "cvv",
            "cvc",
            "expiry",
            "expiration",
            "bank_account",
            "bankaccount",
            "routing_number",
            "iban",
            "swift",
            "bic",
            "payment",
            "salary",
            "income",
            "balance",
            "transaction",
            "price",
            "amount",
            "fee",
        ],
        "authentication": [
            "password",
            "passwd",
            "pwd",
            "pass",
            "secret",
            "token",
            "auth",
            "api_key",
            "apikey",
            "access_token",
            "refresh_token",
            "private_key",
            "credential",
            "session",
            "cookie",
            "hash",
            "salt",
            "otp",
        ],
        "healthcare": [
            "patient",
            "patient_id",
            "medical",
            "health",
            "diagnosis",
            "symptom",
            "prescription",
            "medication",
            "drug",
            "treatment",
            "doctor",
            "hospital",
            "clinic",
            "insurance",
            "policy",
            "blood",
            "allergy",
        ],
    }

    def __init__(self):
        """Initialize the data leak scanner."""
        self._compile_all_patterns()

    def _compile_all_patterns(self):
        """Compile all regex patterns for performance."""
        self._compiled_patterns = {}

        # Compile email patterns
        for name, pattern in self.EMAIL_PATTERNS.items():
            self._compiled_patterns[name] = {
                "regex": re.compile(pattern, re.IGNORECASE),
                "description": f"Email ({name})",
                "category": DataCategory.PERSONAL,
                "severity": "high",
                "compliance": [ComplianceFramework.GDPR, ComplianceFramework.CCPA],
            }

        # Compile all pattern categories
        all_pattern_dicts = [
            self.REGIONAL_PII_PATTERNS,
            self.FINANCIAL_PATTERNS,
            self.AUTH_PATTERNS,
            self.HEALTHCARE_PATTERNS,
            self.BEHAVIORAL_PATTERNS,
        ]

        for pattern_dict in all_pattern_dicts:
            for name, info in pattern_dict.items():
                self._compiled_patterns[name] = {
                    "regex": re.compile(info["pattern"], re.IGNORECASE),
                    "description": info["description"],
                    "category": info["category"],
                    "severity": info["severity"],
                    "compliance": info["compliance"],
                }

    def scan_text(self, text: str, max_samples: int = 5) -> Dict[str, Any]:
        """Scan text for sensitive data patterns.

        Args:
            text: Text content to scan.
            max_samples: Maximum number of samples to collect per pattern.

        Returns:
            Dict with findings and summary.
        """
        if not text:
            return self._empty_result()

        findings = []
        category_counts = {cat: 0 for cat in DataCategory}
        compliance_flags = set()

        for name, info in self._compiled_patterns.items():
            matches = info["regex"].findall(text)
            if matches:
                unique_matches = list(set(matches))[:max_samples]
                count = len(matches)

                finding = DataLeakFinding(
                    category=info["category"],
                    data_type=name,
                    severity=info["severity"],
                    count=count,
                    samples=self._sanitize_samples(unique_matches, name),
                    compliance_impact=info["compliance"],
                    description=info["description"],
                )
                findings.append(finding)
                category_counts[info["category"]] += count
                compliance_flags.update(info["compliance"])

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        findings.sort(key=lambda x: severity_order.get(x.severity, 4))

        return self._build_result(findings, category_counts, compliance_flags)

    def scan_json_documents(self, documents: List[Dict]) -> Dict[str, Any]:
        """Scan JSON documents for sensitive data.

        Args:
            documents: List of JSON document dicts.

        Returns:
            Dict with comprehensive findings.
        """
        all_text = json.dumps(documents, default=str)
        text_findings = self.scan_text(all_text)

        # Also analyze field names
        field_findings = self.analyze_field_names(documents)

        return {
            **text_findings,
            "field_analysis": field_findings,
            "document_count": len(documents),
        }

    def analyze_field_names(self, documents: List[Dict]) -> Dict[str, Any]:
        """Analyze field names in documents for sensitivity indicators.

        Args:
            documents: List of JSON document dicts.

        Returns:
            Dict with field name analysis.
        """
        all_fields = set()

        def extract_fields(obj, prefix=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    full_key = f"{prefix}.{key}" if prefix else key
                    all_fields.add(full_key.lower())
                    if isinstance(value, (dict, list)):
                        extract_fields(value, full_key)
            elif isinstance(obj, list):
                for item in obj[:5]:  # Limit list traversal
                    extract_fields(item, prefix)

        for doc in documents[:100]:  # Limit document count
            extract_fields(doc)

        findings = {category: [] for category in self.SENSITIVE_FIELD_PATTERNS}

        for field_name in all_fields:
            for category, patterns in self.SENSITIVE_FIELD_PATTERNS.items():
                for pattern in patterns:
                    if pattern in field_name:
                        findings[category].append(field_name)
                        break

        return {
            "total_fields": len(all_fields),
            "sensitive_fields": findings,
            "has_personal_fields": len(findings["personal"]) > 0,
            "has_financial_fields": len(findings["financial"]) > 0,
            "has_auth_fields": len(findings["authentication"]) > 0,
            "has_healthcare_fields": len(findings["healthcare"]) > 0,
        }

    def detect_emails(self, text: str, max_results: int = 100) -> Dict[str, Any]:
        """Specialized email detection with categorization.

        Args:
            text: Text to scan for emails.
            max_results: Maximum emails to return.

        Returns:
            Dict with email findings.
        """
        email_pattern = re.compile(self.EMAIL_PATTERNS["standard_email"], re.IGNORECASE)
        matches = email_pattern.findall(text)

        if not matches:
            return {"found": False, "count": 0, "emails": [], "domains": {}}

        unique_emails = list(set(matches))[:max_results]

        # Categorize by domain
        domains = {}
        corporate_domains = []
        personal_domains = [
            "gmail.com",
            "yahoo.com",
            "outlook.com",
            "hotmail.com",
            "protonmail.com",
            "icloud.com",
            "aol.com",
            "mail.com",
        ]

        for email in unique_emails:
            domain = email.split("@")[-1].lower()
            domains[domain] = domains.get(domain, 0) + 1

        # Identify potential corporate emails
        for domain, count in domains.items():
            if domain not in personal_domains and count > 1:
                corporate_domains.append(domain)

        return {
            "found": True,
            "count": len(matches),
            "unique_count": len(unique_emails),
            "emails": [self._mask_email(e) for e in unique_emails[:20]],
            "domains": dict(sorted(domains.items(), key=lambda x: x[1], reverse=True)[:10]),
            "corporate_domains": corporate_domains,
            "has_corporate_emails": len(corporate_domains) > 0,
        }

    def detect_credentials(self, text: str) -> Dict[str, Any]:
        """Specialized credential/secret detection.

        Args:
            text: Text to scan.

        Returns:
            Dict with credential findings.
        """
        findings = []

        credential_patterns = {
            "aws_access_key": self.AUTH_PATTERNS["aws_access_key"]["pattern"],
            "github_token": self.AUTH_PATTERNS["github_token"]["pattern"],
            "google_api_key": self.AUTH_PATTERNS["google_api_key"]["pattern"],
            "jwt_token": self.AUTH_PATTERNS["jwt_token"]["pattern"],
            "private_key": self.AUTH_PATTERNS["private_key"]["pattern"],
            "password_field": self.AUTH_PATTERNS["password_field"]["pattern"],
        }

        for name, pattern in credential_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                findings.append(
                    {
                        "type": name,
                        "count": len(matches),
                        "severity": "critical",
                        "samples": ["[REDACTED]"] * min(len(matches), 3),
                    }
                )

        return {
            "credentials_found": len(findings) > 0,
            "findings": findings,
            "severity": "critical" if findings else "none",
            "requires_immediate_action": len(findings) > 0,
        }

    def assess_compliance_risk(self, scan_result: Dict) -> Dict[str, Any]:
        """Assess compliance risk based on scan results.

        Args:
            scan_result: Result from scan_text or scan_json_documents.

        Returns:
            Dict with compliance assessment.
        """
        compliance_risks = {framework: False for framework in ComplianceFramework}
        violations = []

        for finding in scan_result.get("findings", []):
            if hasattr(finding, "compliance_impact"):
                for framework in finding.compliance_impact:
                    compliance_risks[framework] = True
                    violations.append(
                        {
                            "framework": framework.value,
                            "data_type": finding.data_type,
                            "severity": finding.severity,
                            "count": finding.count,
                        }
                    )

        # Determine overall risk level
        critical_count = sum(
            1
            for f in scan_result.get("findings", [])
            if hasattr(f, "severity") and f.severity == "critical"
        )

        if critical_count > 0:
            risk_level = "critical"
        elif any(compliance_risks.values()):
            risk_level = "high"
        elif scan_result.get("total_findings", 0) > 0:
            risk_level = "medium"
        else:
            risk_level = "low"

        return {
            "risk_level": risk_level,
            "compliance_frameworks_affected": [f.value for f, v in compliance_risks.items() if v],
            "violations": violations,
            "gdpr_impact": compliance_risks[ComplianceFramework.GDPR],
            "ccpa_impact": compliance_risks[ComplianceFramework.CCPA],
            "hipaa_impact": compliance_risks[ComplianceFramework.HIPAA],
            "pci_dss_impact": compliance_risks[ComplianceFramework.PCI_DSS],
            "recommendations": self._get_compliance_recommendations(compliance_risks),
        }

    def _get_compliance_recommendations(self, risks: Dict) -> List[str]:
        """Generate compliance-specific recommendations."""
        recommendations = []

        if risks.get(ComplianceFramework.GDPR):
            recommendations.extend(
                [
                    "GDPR: Notify data subjects within 72 hours of breach discovery",
                    "GDPR: Report to supervisory authority if risk to individuals",
                    "GDPR: Document the breach in internal records",
                ]
            )

        if risks.get(ComplianceFramework.CCPA):
            recommendations.extend(
                [
                    "CCPA: Notify affected California residents",
                    "CCPA: Report to California Attorney General if >500 residents affected",
                ]
            )

        if risks.get(ComplianceFramework.HIPAA):
            recommendations.extend(
                [
                    "HIPAA: Report to HHS within 60 days",
                    "HIPAA: Notify affected individuals without unreasonable delay",
                    "HIPAA: If >500 affected, notify prominent media outlets",
                ]
            )

        if risks.get(ComplianceFramework.PCI_DSS):
            recommendations.extend(
                [
                    "PCI-DSS: Notify payment card brands immediately",
                    "PCI-DSS: Engage a PCI Forensic Investigator (PFI)",
                    "PCI-DSS: Preserve all evidence for forensic analysis",
                ]
            )

        return recommendations

    def _sanitize_samples(self, samples: List[str], data_type: str) -> List[str]:
        """Sanitize samples for safe display."""
        sanitized = []
        sensitive_types = [
            "credit_card",
            "ssn",
            "password",
            "api_key",
            "private_key",
            "aws_access_key",
            "aws_secret_key",
            "github_token",
            "jwt_token",
        ]

        for sample in samples:
            if any(t in data_type.lower() for t in sensitive_types):
                sanitized.append("[REDACTED]")
            elif "email" in data_type.lower():
                sanitized.append(self._mask_email(sample))
            elif len(sample) > 8:
                sanitized.append(f"{sample[:4]}***{sample[-4:]}")
            else:
                sanitized.append("***")

        return sanitized

    def _mask_email(self, email: str) -> str:
        """Mask email for safe display."""
        try:
            local, domain = email.split("@")
            if len(local) > 2:
                return f"{local[0]}***{local[-1]}@{domain}"
            return f"***@{domain}"
        except ValueError:
            return "***@***"

    def _empty_result(self) -> Dict[str, Any]:
        """Return empty result structure."""
        return {
            "found": False,
            "findings": [],
            "total_findings": 0,
            "categories": {},
            "severity_summary": {},
            "compliance_impact": [],
        }

    def _build_result(
        self,
        findings: List[DataLeakFinding],
        category_counts: Dict,
        compliance_flags: set,
    ) -> Dict[str, Any]:
        """Build comprehensive result dict."""
        severity_summary = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for finding in findings:
            severity_summary[finding.severity] = severity_summary.get(finding.severity, 0) + 1

        return {
            "found": len(findings) > 0,
            "findings": findings,
            "total_findings": len(findings),
            "categories": {cat.value: count for cat, count in category_counts.items() if count > 0},
            "severity_summary": severity_summary,
            "compliance_impact": [f.value for f in compliance_flags],
            "has_critical": severity_summary["critical"] > 0,
            "has_pii": category_counts.get(DataCategory.PERSONAL, 0) > 0,
            "has_financial": category_counts.get(DataCategory.FINANCIAL, 0) > 0,
            "has_healthcare": category_counts.get(DataCategory.HEALTHCARE, 0) > 0,
            "has_credentials": category_counts.get(DataCategory.AUTHENTICATION, 0) > 0,
        }

    def generate_report(self, scan_result: Dict) -> str:
        """Generate a human-readable report from scan results.

        Args:
            scan_result: Result from scanning methods.

        Returns:
            Formatted report string.
        """
        lines = [
            "=" * 60,
            "DATA LEAK SCAN REPORT",
            "=" * 60,
            "",
        ]

        if not scan_result.get("found"):
            lines.append("No sensitive data detected.")
            return "\n".join(lines)

        # Summary
        lines.extend(
            [
                f"Total Findings: {scan_result.get('total_findings', 0)}",
                f"Critical Issues: {scan_result.get('severity_summary', {}).get('critical', 0)}",
                f"High Issues: {scan_result.get('severity_summary', {}).get('high', 0)}",
                "",
                "Categories Affected:",
            ]
        )

        for category, count in scan_result.get("categories", {}).items():
            lines.append(f"  - {category}: {count} items")

        if scan_result.get("compliance_impact"):
            lines.extend(
                [
                    "",
                    "Compliance Frameworks Affected:",
                ]
            )
            for framework in scan_result["compliance_impact"]:
                lines.append(f"  - {framework.upper()}")

        lines.extend(
            [
                "",
                "-" * 60,
                "DETAILED FINDINGS:",
                "-" * 60,
            ]
        )

        for finding in scan_result.get("findings", [])[:20]:
            lines.extend(
                [
                    "",
                    f"[{finding.severity.upper()}] {finding.description}",
                    f"  Type: {finding.data_type}",
                    f"  Count: {finding.count}",
                    f"  Samples: {', '.join(finding.samples[:3])}",
                ]
            )

        return "\n".join(lines)
