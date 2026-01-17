"""Tests for the cloud provider analyzer."""

from elasticsearch_finder.analyzers.cloud_provider import CloudProviderAnalyzer


class TestCloudProviderAnalyzer:
    """Tests for CloudProviderAnalyzer."""

    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = CloudProviderAnalyzer()

    def test_detect_aws_from_organization(self):
        """Test AWS detection from organization name."""
        assert self.analyzer.detect_from_organization("Amazon.com, Inc.") == "aws"
        assert self.analyzer.detect_from_organization("Amazon Web Services") == "aws"
        assert self.analyzer.detect_from_organization("AWS") == "aws"
        assert self.analyzer.detect_from_organization("Amazon Data Services") == "aws"

    def test_detect_gcp_from_organization(self):
        """Test GCP detection from organization name."""
        assert self.analyzer.detect_from_organization("Google LLC") == "gcp"
        assert self.analyzer.detect_from_organization("Google Cloud") == "gcp"

    def test_detect_azure_from_organization(self):
        """Test Azure detection from organization name."""
        assert self.analyzer.detect_from_organization("Microsoft Corporation") == "azure"
        assert self.analyzer.detect_from_organization("Microsoft Azure") == "azure"

    def test_detect_digitalocean_from_organization(self):
        """Test DigitalOcean detection from organization name."""
        assert self.analyzer.detect_from_organization("DigitalOcean, LLC") == "digitalocean"

    def test_detect_ovh_from_organization(self):
        """Test OVH detection from organization name."""
        assert self.analyzer.detect_from_organization("OVH SAS") == "ovh"
        assert self.analyzer.detect_from_organization("OVHcloud") == "ovh"

    def test_detect_hetzner_from_organization(self):
        """Test Hetzner detection from organization name."""
        assert self.analyzer.detect_from_organization("Hetzner Online GmbH") == "hetzner"

    def test_detect_vultr_from_organization(self):
        """Test Vultr detection from organization name."""
        assert self.analyzer.detect_from_organization("Vultr Holdings, LLC") == "vultr"
        assert self.analyzer.detect_from_organization("Choopa, LLC") == "vultr"

    def test_detect_alibaba_from_organization(self):
        """Test Alibaba detection from organization name."""
        assert self.analyzer.detect_from_organization("Alibaba Cloud") == "alibaba"
        assert self.analyzer.detect_from_organization("Aliyun Computing") == "alibaba"

    def test_no_detection_for_unknown(self):
        """Test that unknown organizations return None."""
        assert self.analyzer.detect_from_organization("Random ISP Inc.") is None
        assert self.analyzer.detect_from_organization("") is None
        assert self.analyzer.detect_from_organization(None) is None

    def test_detect_aws_from_hostname(self):
        """Test AWS detection from hostname."""
        assert self.analyzer.detect_from_hostname("ec2-1-2-3-4.compute-1.amazonaws.com") == "aws"
        assert self.analyzer.detect_from_hostname("ip-10-0-0-1.ec2.internal") is None

    def test_detect_gcp_from_hostname(self):
        """Test GCP detection from hostname."""
        assert self.analyzer.detect_from_hostname("1-2-3-4.bc.googleusercontent.com") == "gcp"

    def test_detect_azure_from_hostname(self):
        """Test Azure detection from hostname."""
        assert self.analyzer.detect_from_hostname("myapp.cloudapp.azure.com") == "azure"

    def test_detect_ovh_from_hostname(self):
        """Test OVH detection from hostname."""
        assert self.analyzer.detect_from_hostname("ns123456.ip-1-2-3.ovh.net") == "ovh"

    def test_detect_from_asn(self):
        """Test detection from ASN."""
        assert self.analyzer.detect_from_asn("AS16509") == "aws"
        assert self.analyzer.detect_from_asn("AS15169") == "gcp"
        assert self.analyzer.detect_from_asn("AS8075") == "azure"
        assert self.analyzer.detect_from_asn("AS14061") == "digitalocean"
        assert self.analyzer.detect_from_asn("AS16276") == "ovh"
        assert self.analyzer.detect_from_asn("AS24940") == "hetzner"

    def test_detect_from_asn_case_insensitive(self):
        """Test ASN detection is case insensitive."""
        assert self.analyzer.detect_from_asn("as16509") == "aws"
        assert self.analyzer.detect_from_asn("As16509") == "aws"

    def test_analyze_comprehensive(self):
        """Test comprehensive analysis."""
        result = self.analyzer.analyze(
            ip="1.2.3.4",
            org="Amazon.com, Inc.",
            hostname="ec2-1-2-3-4.compute-1.amazonaws.com",
        )

        assert result["provider"] == "aws"
        assert result["is_cloud"] is True
        assert result["confidence"] in ["high", "medium"]

    def test_analyze_non_cloud(self):
        """Test analysis of non-cloud IP."""
        result = self.analyzer.analyze(
            ip="1.2.3.4",
            org="Some Random ISP",
        )

        assert result["provider"] is None
        assert result["is_cloud"] is False

    def test_get_provider_info_aws(self):
        """Test getting AWS provider info."""
        info = self.analyzer.get_provider_info("aws")

        assert info["name"] == "Amazon Web Services"
        assert info["short"] == "AWS"
        assert "abuse_contact" in info
        assert "security_contact" in info
        assert "report_url" in info

    def test_get_provider_info_unknown(self):
        """Test getting info for unknown provider."""
        info = self.analyzer.get_provider_info("unknown_provider")
        assert info == {}

    def test_confidence_levels(self):
        """Test confidence levels based on detection method."""
        # Hostname should be high confidence
        result = self.analyzer.analyze(hostname="ec2-1-2-3-4.compute-1.amazonaws.com")
        assert result["confidence"] == "high"

        # Organization should be medium confidence
        result = self.analyzer.analyze(org="Amazon.com, Inc.")
        assert result["confidence"] == "medium"
