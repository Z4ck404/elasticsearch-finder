"""Tests for the DataLeakScanner module."""

import pytest

from elasticsearch_finder.analyzers.data_leak_scanner import (
    ComplianceFramework,
    DataCategory,
    DataLeakScanner,
)


class TestDataLeakScanner:
    """Test suite for DataLeakScanner."""

    @pytest.fixture
    def scanner(self):
        """Create a DataLeakScanner instance."""
        return DataLeakScanner()

    def test_detect_emails(self, scanner):
        """Test email detection."""
        text = """
        Contact us at support@example.com or sales@company.org
        Personal emails: john.doe@gmail.com, jane@yahoo.com
        """
        result = scanner.detect_emails(text)

        assert result["found"] is True
        assert result["count"] >= 4
        assert result["unique_count"] >= 4
        assert len(result["domains"]) >= 2

    def test_detect_credit_cards(self, scanner):
        """Test credit card detection."""
        text = """
        Visa: 4111111111111111
        Mastercard: 5555555555554444
        Amex: 378282246310005
        """
        result = scanner.scan_text(text)

        assert result["found"] is True
        assert result["has_financial"] is True

    def test_detect_ssn(self, scanner):
        """Test SSN detection."""
        text = "SSN: 123-45-6789"
        result = scanner.scan_text(text)

        assert result["found"] is True
        assert "ccpa" in [c.lower() for c in result.get("compliance_impact", [])]

    def test_detect_aws_keys(self, scanner):
        """Test AWS key detection."""
        text = """
        AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
        """
        result = scanner.detect_credentials(text)

        assert result["credentials_found"] is True
        assert result["severity"] == "critical"

    def test_detect_jwt_tokens(self, scanner):
        """Test JWT token detection."""
        text = "token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = scanner.detect_credentials(text)

        assert result["credentials_found"] is True

    def test_detect_github_tokens(self, scanner):
        """Test GitHub token detection."""
        text = "GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        result = scanner.detect_credentials(text)

        assert result["credentials_found"] is True

    def test_scan_json_documents(self, scanner):
        """Test JSON document scanning."""
        documents = [
            {"email": "user@example.com", "password": "secret123"},
            {"name": "John Doe", "ssn": "123-45-6789"},
        ]
        result = scanner.scan_json_documents(documents)

        assert result["found"] is True
        assert result["document_count"] == 2
        assert "field_analysis" in result

    def test_analyze_field_names(self, scanner):
        """Test field name analysis."""
        documents = [
            {
                "user_email": "test@test.com",
                "credit_card_number": "4111111111111111",
                "patient_id": "12345",
            }
        ]
        result = scanner.analyze_field_names(documents)

        assert result["has_personal_fields"] is True
        assert result["has_financial_fields"] is True
        assert result["has_healthcare_fields"] is True

    def test_compliance_assessment(self, scanner):
        """Test compliance risk assessment."""
        # First scan some text with PII
        text = "SSN: 123-45-6789, email: patient@hospital.com"
        scan_result = scanner.scan_text(text)

        # Then assess compliance
        compliance = scanner.assess_compliance_risk(scan_result)

        assert compliance["risk_level"] in ["critical", "high", "medium", "low"]
        assert "recommendations" in compliance

    def test_empty_text_scan(self, scanner):
        """Test scanning empty text."""
        result = scanner.scan_text("")

        assert result["found"] is False
        assert result["total_findings"] == 0

    def test_no_pii_text(self, scanner):
        """Test scanning text without PII."""
        text = "Hello world! This is a normal text without any personal data."
        result = scanner.scan_text(text)

        # Should find no critical PII (might find some false positives)
        assert result.get("has_critical", False) is False

    def test_iban_detection(self, scanner):
        """Test IBAN detection."""
        text = "Bank account: DE89370400440532013000"
        result = scanner.scan_text(text)

        assert result["found"] is True
        assert result["has_financial"] is True

    def test_uk_nino_detection(self, scanner):
        """Test UK National Insurance Number detection."""
        text = "NI Number: AB123456C"
        result = scanner.scan_text(text)

        assert result["found"] is True

    def test_ip_address_detection(self, scanner):
        """Test IP address detection."""
        text = "User IP: 192.168.1.100"
        result = scanner.scan_text(text)

        assert result["found"] is True

    def test_password_hash_detection(self, scanner):
        """Test password hash detection."""
        text = "password_hash: 5f4dcc3b5aa765d61d8327deb882cf99"  # MD5 of 'password'
        result = scanner.scan_text(text)

        assert result["found"] is True
        assert result["has_credentials"] is True

    def test_generate_report(self, scanner):
        """Test report generation."""
        text = "email: test@example.com, ssn: 123-45-6789"
        scan_result = scanner.scan_text(text)
        report = scanner.generate_report(scan_result)

        assert "DATA LEAK SCAN REPORT" in report
        assert len(report) > 100

    def test_sample_sanitization(self, scanner):
        """Test that samples are properly sanitized."""
        text = "credit_card: 4111111111111111"
        result = scanner.scan_text(text)

        # Check that credit card samples are redacted
        for finding in result.get("findings", []):
            if hasattr(finding, "samples"):
                for sample in finding.samples:
                    assert "4111111111111111" not in sample

    def test_email_masking(self, scanner):
        """Test email masking in results."""
        result = scanner._mask_email("john.doe@example.com")
        assert "@example.com" in result
        assert "john.doe" not in result

    def test_data_category_enum(self):
        """Test DataCategory enum values."""
        assert DataCategory.PERSONAL.value == "personal"
        assert DataCategory.FINANCIAL.value == "financial"
        assert DataCategory.HEALTHCARE.value == "healthcare"

    def test_compliance_framework_enum(self):
        """Test ComplianceFramework enum values."""
        assert ComplianceFramework.GDPR.value == "gdpr"
        assert ComplianceFramework.HIPAA.value == "hipaa"
        assert ComplianceFramework.PCI_DSS.value == "pci_dss"


class TestDataLeakScannerEdgeCases:
    """Test edge cases for DataLeakScanner."""

    @pytest.fixture
    def scanner(self):
        return DataLeakScanner()

    def test_nested_json_field_extraction(self, scanner):
        """Test field extraction from nested JSON."""
        documents = [
            {"user": {"profile": {"email": "nested@example.com", "phone": "123-456-7890"}}}
        ]
        result = scanner.analyze_field_names(documents)

        assert result["total_fields"] > 0

    def test_large_text_handling(self, scanner):
        """Test handling of large text."""
        large_text = "email: test@example.com " * 10000
        result = scanner.scan_text(large_text)

        assert result["found"] is True
        # Should have limited samples
        for finding in result.get("findings", []):
            if hasattr(finding, "samples"):
                assert len(finding.samples) <= 5

    def test_mixed_case_patterns(self, scanner):
        """Test detection of mixed case patterns."""
        text = """
        EMAIL: TEST@EXAMPLE.COM
        Password: MySecret123
        """
        result = scanner.scan_text(text)

        assert result["found"] is True

    def test_unicode_handling(self, scanner):
        """Test handling of unicode characters."""
        text = "email: tëst@éxample.com, name: José García"
        result = scanner.scan_text(text)

        # Should not crash on unicode
        assert isinstance(result, dict)
