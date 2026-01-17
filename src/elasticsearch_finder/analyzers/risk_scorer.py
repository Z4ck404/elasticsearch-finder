"""Risk scoring for Elasticsearch Finder."""

from typing import Any, Dict, List


class RiskScorer:
    """Score the risk level of open Elasticsearch instances."""

    # Weight factors for risk scoring
    WEIGHTS = {
        "data_size": 0.10,
        "index_sensitivity": 0.20,
        "pii_detected": 0.25,
        "credentials_detected": 0.15,
        "cloud_exposure": 0.10,
        "node_count": 0.05,
        "accessibility": 0.10,
        "compliance_risk": 0.05,
    }

    # Size thresholds (in bytes)
    SIZE_THRESHOLDS = {
        "tiny": 1024 * 1024,  # 1 MB
        "small": 100 * 1024 * 1024,  # 100 MB
        "medium": 1024 * 1024 * 1024,  # 1 GB
        "large": 10 * 1024 * 1024 * 1024,  # 10 GB
        "huge": 100 * 1024 * 1024 * 1024,  # 100 GB
    }

    # Cloud provider risk levels
    CLOUD_PROVIDER_RISKS = {
        "aws": 85,
        "gcp": 85,
        "azure": 85,
        "alibaba": 80,
        "tencent": 80,
        "oracle": 75,
        "digitalocean": 70,
        "ovh": 70,
        "linode": 70,
        "vultr": 65,
        "hetzner": 65,
        "scaleway": 60,
        "contabo": 55,
        "unknown": 50,
    }

    def __init__(self):
        """Initialize the risk scorer."""
        pass

    def calculate_risk_score(
        self,
        cluster_size_bytes: int = 0,
        index_analysis: dict = None,
        pii_analysis: dict = None,
        cloud_analysis: dict = None,
        node_count: int = 0,
        is_accessible: bool = True,
        data_leak_analysis: dict = None,
        credentials_analysis: dict = None,
    ) -> dict:
        """Calculate overall risk score for an Elasticsearch instance.

        Args:
            cluster_size_bytes: Size of the cluster in bytes.
            index_analysis: Result from PIIScanner.analyze_indices().
            pii_analysis: Result from PIIScanner.scan_text().
            cloud_analysis: Result from CloudProviderAnalyzer.analyze().
            node_count: Number of nodes in the cluster.
            is_accessible: Whether the cluster is publicly accessible.
            data_leak_analysis: Result from DataLeakScanner.scan_text().
            credentials_analysis: Result from DataLeakScanner.detect_credentials().

        Returns:
            Dict with risk score and breakdown.
        """
        scores = {}

        # Data size score (0-100)
        scores["data_size"] = self._score_data_size(cluster_size_bytes)

        # Index sensitivity score (0-100)
        scores["index_sensitivity"] = self._score_index_sensitivity(index_analysis)

        # PII detection score (0-100)
        scores["pii_detected"] = self._score_pii_detection(pii_analysis, data_leak_analysis)

        # Credentials detection score (0-100)
        scores["credentials_detected"] = self._score_credentials_detection(
            credentials_analysis, data_leak_analysis
        )

        # Cloud exposure score (0-100)
        scores["cloud_exposure"] = self._score_cloud_exposure(cloud_analysis)

        # Node count score (0-100)
        scores["node_count"] = self._score_node_count(node_count)

        # Accessibility score (0-100)
        scores["accessibility"] = 100 if is_accessible else 0

        # Compliance risk score (0-100)
        scores["compliance_risk"] = self._score_compliance_risk(data_leak_analysis)

        # Calculate weighted total
        total_score = sum(scores[key] * self.WEIGHTS.get(key, 0) for key in scores)

        # Determine risk level
        risk_level = self._get_risk_level(total_score)

        # Generate threat indicators
        threat_indicators = self._generate_threat_indicators(
            scores, cloud_analysis, data_leak_analysis
        )

        return {
            "total_score": round(total_score, 2),
            "risk_level": risk_level,
            "component_scores": scores,
            "weights": self.WEIGHTS,
            "recommendations": self._get_recommendations(scores, risk_level, cloud_analysis),
            "threat_indicators": threat_indicators,
            "requires_immediate_action": total_score >= 80
            or scores.get("credentials_detected", 0) >= 70,
        }

    def _score_data_size(self, size_bytes: int) -> float:
        """Score based on data size."""
        if size_bytes <= 0:
            return 0
        elif size_bytes < self.SIZE_THRESHOLDS["tiny"]:
            return 10
        elif size_bytes < self.SIZE_THRESHOLDS["small"]:
            return 30
        elif size_bytes < self.SIZE_THRESHOLDS["medium"]:
            return 50
        elif size_bytes < self.SIZE_THRESHOLDS["large"]:
            return 70
        elif size_bytes < self.SIZE_THRESHOLDS["huge"]:
            return 90
        else:
            return 100

    def _score_index_sensitivity(self, analysis: dict) -> float:
        """Score based on index sensitivity analysis."""
        if not analysis:
            return 0

        if analysis.get("has_critical"):
            return 100
        elif len(analysis.get("high_risk_indices", [])) > 0:
            return 80
        elif analysis.get("sensitive_indices_count", 0) > 0:
            ratio = analysis["sensitive_indices_count"] / max(analysis.get("total_indices", 1), 1)
            return min(60 + (ratio * 40), 75)
        else:
            return 10

    def _score_pii_detection(self, analysis: dict, data_leak_analysis: dict = None) -> float:
        """Score based on PII detection analysis."""
        score = 0

        # Score from traditional PII analysis
        if analysis and analysis.get("found"):
            score += 30

            if analysis.get("has_critical"):
                score += 40

            if analysis.get("has_gdpr_data"):
                score += 20

            pii_count = analysis.get("total_pii_count", 0)
            if pii_count > 100:
                score += 10
            elif pii_count > 10:
                score += 5

        # Additional score from data leak analysis
        if data_leak_analysis and data_leak_analysis.get("found"):
            if data_leak_analysis.get("has_pii"):
                score += 20
            if data_leak_analysis.get("has_healthcare"):
                score += 30  # HIPAA data is critical
            if data_leak_analysis.get("severity_summary", {}).get("critical", 0) > 0:
                score += 20

        return min(score, 100)

    def _score_credentials_detection(
        self, credentials_analysis: dict = None, data_leak_analysis: dict = None
    ) -> float:
        """Score based on credentials/secrets detection."""
        score = 0

        if credentials_analysis and credentials_analysis.get("credentials_found"):
            score += 70
            findings_count = len(credentials_analysis.get("findings", []))
            if findings_count > 5:
                score += 30
            elif findings_count > 1:
                score += 15

        if data_leak_analysis and data_leak_analysis.get("has_credentials"):
            score += 30

        return min(score, 100)

    def _score_cloud_exposure(self, analysis: dict) -> float:
        """Score based on cloud exposure analysis."""
        if not analysis:
            return 50  # Unknown, assume moderate risk

        if not analysis.get("is_cloud"):
            return 30  # Non-cloud might be intentional, lower score

        # Use provider-specific risk levels
        provider = analysis.get("provider", "unknown")
        base_score = self.CLOUD_PROVIDER_RISKS.get(provider, 50)

        # Adjust based on confidence
        confidence = analysis.get("confidence", "low")
        if confidence == "high":
            return base_score
        elif confidence == "medium":
            return int(base_score * 0.9)
        else:
            return int(base_score * 0.75)

    def _score_node_count(self, node_count: int) -> float:
        """Score based on node count (larger clusters = more important)."""
        if node_count <= 0:
            return 0
        elif node_count == 1:
            return 20
        elif node_count <= 3:
            return 40
        elif node_count <= 10:
            return 70
        else:
            return 100

    def _score_compliance_risk(self, data_leak_analysis: dict = None) -> float:
        """Score based on compliance framework impact."""
        if not data_leak_analysis:
            return 0

        score = 0
        compliance_impact = data_leak_analysis.get("compliance_impact", [])

        # High-risk compliance frameworks
        high_risk_frameworks = ["gdpr", "hipaa", "pci_dss"]
        for framework in compliance_impact:
            if framework in high_risk_frameworks:
                score += 30
            else:
                score += 10

        # Factor in severity
        if data_leak_analysis.get("has_critical"):
            score += 20

        return min(score, 100)

    def _generate_threat_indicators(
        self,
        scores: dict,
        cloud_analysis: dict = None,
        data_leak_analysis: dict = None,
    ) -> List[Dict[str, Any]]:
        """Generate threat indicators for the instance."""
        indicators = []

        # Critical threats
        if scores.get("credentials_detected", 0) >= 70:
            indicators.append(
                {
                    "indicator": "LEAKED_CREDENTIALS",
                    "severity": "critical",
                    "description": "API keys, tokens, or passwords detected in data",
                    "mitre_attack": "T1552 - Unsecured Credentials",
                }
            )

        if scores.get("pii_detected", 0) >= 80:
            indicators.append(
                {
                    "indicator": "MASSIVE_PII_EXPOSURE",
                    "severity": "critical",
                    "description": "Large-scale personal data exposure detected",
                    "mitre_attack": "T1530 - Data from Cloud Storage",
                }
            )

        # High threats
        if cloud_analysis and cloud_analysis.get("is_cloud"):
            provider = cloud_analysis.get("provider", "unknown")
            indicators.append(
                {
                    "indicator": f"CLOUD_EXPOSURE_{provider.upper()}",
                    "severity": "high",
                    "description": f"Instance hosted on {provider} cloud without authentication",
                    "mitre_attack": "T1190 - Exploit Public-Facing Application",
                }
            )

        if data_leak_analysis and data_leak_analysis.get("has_financial"):
            indicators.append(
                {
                    "indicator": "FINANCIAL_DATA_EXPOSURE",
                    "severity": "critical",
                    "description": "Financial data (credit cards, bank accounts) detected",
                    "mitre_attack": "T1005 - Data from Local System",
                }
            )

        if data_leak_analysis and data_leak_analysis.get("has_healthcare"):
            indicators.append(
                {
                    "indicator": "PHI_EXPOSURE",
                    "severity": "critical",
                    "description": "Protected Health Information (PHI) detected - HIPAA violation",
                    "mitre_attack": "T1530 - Data from Cloud Storage",
                }
            )

        # Medium threats
        if scores.get("index_sensitivity", 0) >= 60:
            indicators.append(
                {
                    "indicator": "SENSITIVE_INDEX_NAMES",
                    "severity": "medium",
                    "description": "Index names suggest sensitive data categories",
                    "mitre_attack": "T1083 - File and Directory Discovery",
                }
            )

        return indicators

    def _get_risk_level(self, score: float) -> str:
        """Determine risk level from score."""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 20:
            return "low"
        else:
            return "informational"

    def _get_recommendations(
        self,
        scores: dict,
        risk_level: str,
        cloud_analysis: dict = None,
    ) -> list:
        """Generate recommendations based on scores."""
        recommendations = []

        if risk_level in ["critical", "high"]:
            recommendations.append(
                {
                    "priority": "urgent",
                    "action": "Report immediately to the organization",
                    "details": "This instance contains sensitive data and should be secured ASAP",
                }
            )

        if scores.get("pii_detected", 0) > 50:
            recommendations.append(
                {
                    "priority": "high",
                    "action": "PII Data Exposure",
                    "details": "Personal data detected. May require GDPR/CCPA notification.",
                }
            )

        if scores.get("credentials_detected", 0) > 50:
            recommendations.append(
                {
                    "priority": "critical",
                    "action": "Credential Exposure Detected",
                    "details": "API keys, tokens, or passwords found. Immediate rotation required.",
                }
            )

        if scores.get("index_sensitivity", 0) > 70:
            recommendations.append(
                {
                    "priority": "high",
                    "action": "Sensitive Index Names Detected",
                    "details": "Index names suggest sensitive data categories (healthcare, financial, auth).",
                }
            )

        if scores.get("cloud_exposure", 0) > 60:
            provider_info = ""
            if cloud_analysis and cloud_analysis.get("provider"):
                provider = cloud_analysis["provider"]
                provider_info = f" ({provider.upper()})"
            recommendations.append(
                {
                    "priority": "medium",
                    "action": f"Cloud Provider Detected{provider_info}",
                    "details": "Consider reporting via cloud provider's abuse contact as well.",
                }
            )

        if scores.get("compliance_risk", 0) > 50:
            recommendations.append(
                {
                    "priority": "high",
                    "action": "Compliance Framework Violation",
                    "details": "Data exposure may violate GDPR, HIPAA, PCI-DSS, or other regulations.",
                }
            )

        if scores.get("data_size", 0) > 70:
            recommendations.append(
                {
                    "priority": "medium",
                    "action": "Large Dataset Exposed",
                    "details": "Significant amount of data is accessible.",
                }
            )

        return recommendations

    def get_severity_color(self, risk_level: str) -> str:
        """Get color for risk level (for terminal output)."""
        colors = {
            "critical": "red",
            "high": "yellow",
            "medium": "cyan",
            "low": "green",
            "informational": "white",
        }
        return colors.get(risk_level, "white")

    def format_score_display(self, risk_result: dict) -> str:
        """Format risk score for display."""
        score = risk_result["total_score"]
        level = risk_result["risk_level"]

        # Create visual bar
        bar_length = 20
        filled = int(score / 100 * bar_length)
        bar = "█" * filled + "░" * (bar_length - filled)

        return f"[{bar}] {score:.1f}/100 ({level.upper()})"

    def generate_executive_summary(self, risk_result: dict, cloud_analysis: dict = None) -> str:
        """Generate an executive summary for reporting.

        Args:
            risk_result: Result from calculate_risk_score().
            cloud_analysis: Result from CloudProviderAnalyzer.analyze().

        Returns:
            Formatted executive summary string.
        """
        lines = [
            "=" * 60,
            "EXECUTIVE RISK SUMMARY",
            "=" * 60,
            "",
            f"Overall Risk Score: {risk_result['total_score']:.1f}/100",
            f"Risk Level: {risk_result['risk_level'].upper()}",
            "",
        ]

        if risk_result.get("requires_immediate_action"):
            lines.extend(
                [
                    "⚠️  IMMEDIATE ACTION REQUIRED ⚠️",
                    "",
                ]
            )

        # Component breakdown
        lines.extend(
            [
                "Risk Component Breakdown:",
                "-" * 40,
            ]
        )
        for component, score in risk_result.get("component_scores", {}).items():
            weight = self.WEIGHTS.get(component, 0)
            contribution = score * weight
            lines.append(f"  {component}: {score:.0f} (contributes {contribution:.1f})")

        # Threat indicators
        if risk_result.get("threat_indicators"):
            lines.extend(
                [
                    "",
                    "Threat Indicators:",
                    "-" * 40,
                ]
            )
            for indicator in risk_result["threat_indicators"]:
                lines.append(f"  [{indicator['severity'].upper()}] {indicator['indicator']}")
                lines.append(f"      {indicator['description']}")
                if indicator.get("mitre_attack"):
                    lines.append(f"      MITRE ATT&CK: {indicator['mitre_attack']}")

        # Cloud provider info
        if cloud_analysis and cloud_analysis.get("is_cloud"):
            lines.extend(
                [
                    "",
                    "Cloud Provider Information:",
                    "-" * 40,
                    f"  Provider: {cloud_analysis.get('provider', 'Unknown').upper()}",
                    f"  Detection Confidence: {cloud_analysis.get('confidence', 'Unknown')}",
                ]
            )

        # Recommendations
        if risk_result.get("recommendations"):
            lines.extend(
                [
                    "",
                    "Recommended Actions:",
                    "-" * 40,
                ]
            )
            for rec in risk_result["recommendations"]:
                lines.append(f"  [{rec['priority'].upper()}] {rec['action']}")
                lines.append(f"      {rec['details']}")

        lines.append("")
        lines.append("=" * 60)

        return "\n".join(lines)

    def calculate_data_exposure_estimate(
        self,
        document_count: int,
        cluster_size_bytes: int,
        pii_analysis: dict = None,
    ) -> Dict[str, Any]:
        """Estimate the scale of data exposure.

        Args:
            document_count: Number of documents in the cluster.
            cluster_size_bytes: Size in bytes.
            pii_analysis: PII analysis results.

        Returns:
            Dict with exposure estimates.
        """
        exposure = {
            "document_count": document_count,
            "size_bytes": cluster_size_bytes,
            "size_human": self._format_size(cluster_size_bytes),
            "estimated_records_affected": 0,
            "pii_types_exposed": [],
            "exposure_severity": "unknown",
        }

        # Estimate affected records
        if pii_analysis and pii_analysis.get("found"):
            exposure["estimated_records_affected"] = min(
                document_count,
                pii_analysis.get("total_pii_count", 0) * 10,  # Rough estimate
            )

            # List PII types
            for finding in pii_analysis.get("findings", []):
                if hasattr(finding, "data_type"):
                    exposure["pii_types_exposed"].append(finding.data_type)
                elif isinstance(finding, dict):
                    exposure["pii_types_exposed"].append(finding.get("type", "unknown"))

        # Determine severity based on scale
        if exposure["estimated_records_affected"] > 100000:
            exposure["exposure_severity"] = "massive"
        elif exposure["estimated_records_affected"] > 10000:
            exposure["exposure_severity"] = "large"
        elif exposure["estimated_records_affected"] > 1000:
            exposure["exposure_severity"] = "medium"
        elif exposure["estimated_records_affected"] > 0:
            exposure["exposure_severity"] = "small"

        return exposure

    def _format_size(self, size_bytes: int) -> str:
        """Format byte size to human readable."""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.2f} PB"
