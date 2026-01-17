"""Cloud provider detection for Elasticsearch Finder."""

import ipaddress
import re
from typing import Optional


class CloudProviderAnalyzer:
    """Analyze and detect cloud providers from IP addresses and organization names."""

    # Known cloud provider patterns in organization names
    ORG_PATTERNS = {
        "aws": [
            r"amazon",
            r"aws",
            r"ec2",
            r"amazon\.com",
            r"amazon web services",
            r"amazon data services",
        ],
        "gcp": [
            r"google",
            r"gcp",
            r"google cloud",
            r"google llc",
        ],
        "azure": [
            r"microsoft",
            r"azure",
            r"microsoft corporation",
            r"microsoft azure",
        ],
        "digitalocean": [
            r"digitalocean",
            r"digital ocean",
        ],
        "ovh": [
            r"ovh",
            r"ovhcloud",
            r"ovh sas",
            r"ovh hosting",
        ],
        "linode": [
            r"linode",
            r"akamai connected cloud",
            r"akamai technologies",
        ],
        "vultr": [
            r"vultr",
            r"choopa",
            r"the constant company",
        ],
        "hetzner": [
            r"hetzner",
            r"hetzner online",
        ],
        "alibaba": [
            r"alibaba",
            r"alicloud",
            r"aliyun",
            r"alibaba cloud",
        ],
        "oracle": [
            r"oracle",
            r"oracle cloud",
            r"oracle corporation",
        ],
        "ibm": [
            r"ibm",
            r"softlayer",
            r"ibm cloud",
        ],
        "scaleway": [
            r"scaleway",
            r"online\.net",
            r"iliad",
        ],
        "upcloud": [
            r"upcloud",
        ],
        "contabo": [
            r"contabo",
        ],
        "ionos": [
            r"ionos",
            r"1&1",
            r"1und1",
        ],
        "tencent": [
            r"tencent",
            r"tencent cloud",
            r"qcloud",
        ],
        "yandex": [
            r"yandex",
            r"yandex cloud",
            r"yandex\.cloud",
        ],
        "huawei": [
            r"huawei",
            r"huawei cloud",
        ],
        "cloudflare": [
            r"cloudflare",
            r"cf-",
        ],
        "fastly": [
            r"fastly",
        ],
        "rackspace": [
            r"rackspace",
        ],
        "equinix": [
            r"equinix",
            r"packet",
        ],
        "leaseweb": [
            r"leaseweb",
        ],
        "kamatera": [
            r"kamatera",
        ],
        "hostinger": [
            r"hostinger",
        ],
    }

    # Known cloud provider ASN prefixes (partial list)
    CLOUD_ASNS = {
        "aws": ["AS16509", "AS14618", "AS7224", "AS8987", "AS38895"],
        "gcp": ["AS15169", "AS396982", "AS36040", "AS395973"],
        "azure": ["AS8075", "AS12076", "AS3598", "AS52075"],
        "digitalocean": ["AS14061", "AS200130", "AS202018"],
        "ovh": ["AS16276", "AS35540"],
        "linode": ["AS63949", "AS132892", "AS396998"],
        "vultr": ["AS20473", "AS64515"],
        "hetzner": ["AS24940", "AS213230"],
        "alibaba": ["AS45102", "AS37963", "AS45096"],
        "oracle": ["AS31898", "AS7160"],
        "tencent": ["AS45090", "AS132591", "AS132203"],
        "yandex": ["AS13238", "AS200350", "AS208722"],
        "huawei": ["AS136907", "AS55990"],
        "cloudflare": ["AS13335", "AS209242", "AS395747"],
        "fastly": ["AS54113", "AS19661"],
        "rackspace": ["AS27357", "AS19994"],
    }

    # Hostname patterns
    HOSTNAME_PATTERNS = {
        "aws": [
            r"\.amazonaws\.com",
            r"\.aws\.amazon\.com",
            r"ec2.*\.compute",
            r"compute-\d+\.amazonaws",
        ],
        "gcp": [
            r"\.googleusercontent\.com",
            r"\.google\.com",
            r"\.bc\.googleusercontent\.com",
            r"\.c\..*\.internal",
        ],
        "azure": [
            r"\.azure\.com",
            r"\.azurewebsites\.net",
            r"\.cloudapp\.azure\.com",
            r"\.microsoft\.com",
        ],
        "digitalocean": [
            r"\.digitalocean\.com",
            r"\.digitaloceanspaces\.com",
        ],
        "ovh": [
            r"\.ovh\.net",
            r"\.ovh\.com",
            r"\.cloud\.ovh\.",
            r"\.ovhtelecom\.fr",
        ],
        "linode": [
            r"\.linode\.com",
            r"\.linodeobjects\.com",
            r"\.linodeusercon",
        ],
        "vultr": [
            r"\.vultr\.com",
            r"\.vultrobj\.com",
        ],
        "hetzner": [
            r"\.hetzner\.com",
            r"\.your-server\.de",
            r"\.hetzner\.cloud",
        ],
        "tencent": [
            r"\.tencentcloudapi\.com",
            r"\.myqcloud\.com",
        ],
        "yandex": [
            r"\.yandexcloud\.net",
            r"\.cloud\.yandex\.net",
        ],
        "cloudflare": [
            r"\.cloudflare\.com",
            r"\.workers\.dev",
        ],
    }

    # IP ranges for major cloud providers (partial, for quick checks)
    IP_RANGES = {
        "aws": [
            "3.0.0.0/8",
            "52.0.0.0/8",
            "54.0.0.0/8",
            "18.0.0.0/8",
            "13.0.0.0/8",
            "35.0.0.0/8",
            "44.192.0.0/10",
        ],
        "gcp": [
            "35.184.0.0/13",
            "35.192.0.0/14",
            "35.196.0.0/15",
            "34.64.0.0/10",
            "104.196.0.0/14",
        ],
        "azure": [
            "13.64.0.0/11",
            "40.64.0.0/10",
            "52.224.0.0/11",
            "20.0.0.0/8",
            "104.40.0.0/13",
        ],
        "digitalocean": [
            "104.131.0.0/16",
            "159.65.0.0/16",
            "167.172.0.0/16",
            "206.189.0.0/16",
            "142.93.0.0/16",
        ],
        "ovh": [
            "51.68.0.0/16",
            "51.75.0.0/16",
            "51.77.0.0/16",
            "51.79.0.0/16",
            "51.81.0.0/16",
            "51.83.0.0/16",
            "51.89.0.0/16",
            "51.91.0.0/16",
            "51.178.0.0/16",
            "54.36.0.0/14",
            "145.239.0.0/16",
            "149.56.0.0/16",
        ],
        "hetzner": [
            "65.21.0.0/16",
            "95.216.0.0/16",
            "135.181.0.0/16",
            "162.55.0.0/16",
            "168.119.0.0/16",
        ],
    }

    def __init__(self):
        """Initialize the cloud provider analyzer."""
        self._compile_patterns()

    def _compile_patterns(self):
        """Compile regex patterns for performance."""
        self._org_compiled = {}
        for provider, patterns in self.ORG_PATTERNS.items():
            self._org_compiled[provider] = [re.compile(p, re.IGNORECASE) for p in patterns]

        self._hostname_compiled = {}
        for provider, patterns in self.HOSTNAME_PATTERNS.items():
            self._hostname_compiled[provider] = [re.compile(p, re.IGNORECASE) for p in patterns]

    def detect_from_organization(self, org: str) -> Optional[str]:
        """Detect cloud provider from organization name.

        Args:
            org: Organization name string.

        Returns:
            Cloud provider name or None.
        """
        if not org:
            return None

        for provider, patterns in self._org_compiled.items():
            for pattern in patterns:
                if pattern.search(org):
                    return provider
        return None

    def detect_from_hostname(self, hostname: str) -> Optional[str]:
        """Detect cloud provider from hostname/reverse DNS.

        Args:
            hostname: Hostname or reverse DNS string.

        Returns:
            Cloud provider name or None.
        """
        if not hostname:
            return None

        for provider, patterns in self._hostname_compiled.items():
            for pattern in patterns:
                if pattern.search(hostname):
                    return provider
        return None

    def detect_from_asn(self, asn: str) -> Optional[str]:
        """Detect cloud provider from ASN.

        Args:
            asn: Autonomous System Number string.

        Returns:
            Cloud provider name or None.
        """
        if not asn:
            return None

        for provider, asns in self.CLOUD_ASNS.items():
            if asn.upper() in asns:
                return provider
        return None

    def detect_from_ip(self, ip: str) -> Optional[str]:
        """Detect cloud provider from IP address using known IP ranges.

        Args:
            ip: IP address string.

        Returns:
            Cloud provider name or None.
        """
        if not ip:
            return None

        try:
            ip_obj = ipaddress.ip_address(ip)
            for provider, ranges in self.IP_RANGES.items():
                for cidr in ranges:
                    try:
                        network = ipaddress.ip_network(cidr, strict=False)
                        if ip_obj in network:
                            return provider
                    except ValueError:
                        continue
        except ValueError:
            return None
        return None

    def analyze(
        self,
        ip: str = None,
        org: str = None,
        hostname: str = None,
        asn: str = None,
        isp: str = None,
    ) -> dict:
        """Perform comprehensive cloud provider analysis.

        Args:
            ip: IP address.
            org: Organization name.
            hostname: Hostname or reverse DNS.
            asn: Autonomous System Number.
            isp: Internet Service Provider.

        Returns:
            Dict with cloud provider info.
        """
        result = {
            "provider": None,
            "confidence": "none",
            "detection_method": None,
            "is_cloud": False,
            "details": {},
        }

        # Try detection methods in order of reliability
        detection_methods = [
            ("hostname", self.detect_from_hostname, hostname),
            ("asn", self.detect_from_asn, asn),
            ("organization", self.detect_from_organization, org),
            ("isp", self.detect_from_organization, isp),
            ("ip_range", self.detect_from_ip, ip),
        ]

        for method_name, method, value in detection_methods:
            if value:
                provider = method(value)
                if provider:
                    result["provider"] = provider
                    result["is_cloud"] = True
                    result["detection_method"] = method_name
                    result["confidence"] = self._get_confidence(method_name)
                    break

        result["details"] = {
            "ip": ip,
            "organization": org,
            "hostname": hostname,
            "asn": asn,
            "isp": isp,
        }

        return result

    def _get_confidence(self, method: str) -> str:
        """Get confidence level based on detection method.

        Args:
            method: Detection method name.

        Returns:
            Confidence level string.
        """
        confidence_map = {
            "hostname": "high",
            "asn": "high",
            "ip_range": "medium",
            "organization": "medium",
            "isp": "low",
        }
        return confidence_map.get(method, "low")

    def get_provider_info(self, provider: str) -> dict:
        """Get information about a cloud provider.

        Args:
            provider: Cloud provider name.

        Returns:
            Dict with provider information.
        """
        provider_info = {
            "aws": {
                "name": "Amazon Web Services",
                "short": "AWS",
                "abuse_contact": "abuse@amazonaws.com",
                "security_contact": "aws-security@amazon.com",
                "report_url": "https://aws.amazon.com/security/vulnerability-reporting/",
            },
            "gcp": {
                "name": "Google Cloud Platform",
                "short": "GCP",
                "abuse_contact": "abuse@google.com",
                "security_contact": "security@google.com",
                "report_url": "https://www.google.com/about/appsecurity/",
            },
            "azure": {
                "name": "Microsoft Azure",
                "short": "Azure",
                "abuse_contact": "abuse@microsoft.com",
                "security_contact": "secure@microsoft.com",
                "report_url": "https://www.microsoft.com/en-us/msrc/faqs-report-an-issue",
            },
            "digitalocean": {
                "name": "DigitalOcean",
                "short": "DO",
                "abuse_contact": "abuse@digitalocean.com",
                "security_contact": "security@digitalocean.com",
                "report_url": "https://www.digitalocean.com/security/",
            },
            "ovh": {
                "name": "OVHcloud",
                "short": "OVH",
                "abuse_contact": "abuse@ovh.net",
                "security_contact": "security@ovhcloud.com",
                "report_url": "https://www.ovhcloud.com/en/security/",
            },
            "linode": {
                "name": "Linode (Akamai)",
                "short": "Linode",
                "abuse_contact": "abuse@linode.com",
                "security_contact": "security@linode.com",
                "report_url": "https://www.linode.com/security/",
            },
            "vultr": {
                "name": "Vultr",
                "short": "Vultr",
                "abuse_contact": "abuse@vultr.com",
                "security_contact": "support@vultr.com",
                "report_url": "https://www.vultr.com/legal/aup/",
            },
            "hetzner": {
                "name": "Hetzner Online",
                "short": "Hetzner",
                "abuse_contact": "abuse@hetzner.com",
                "security_contact": "abuse@hetzner.com",
                "report_url": "https://www.hetzner.com/legal/abuse/",
            },
            "alibaba": {
                "name": "Alibaba Cloud",
                "short": "Alibaba",
                "abuse_contact": "abuse@alibabacloud.com",
                "security_contact": "security@alibabacloud.com",
                "report_url": "https://security.alibaba.com/",
            },
            "oracle": {
                "name": "Oracle Cloud",
                "short": "Oracle",
                "abuse_contact": "abuse@oracle.com",
                "security_contact": "secalert_us@oracle.com",
                "report_url": "https://www.oracle.com/security-alerts/",
            },
            "tencent": {
                "name": "Tencent Cloud",
                "short": "Tencent",
                "abuse_contact": "abuse@tencent.com",
                "security_contact": "security@tencent.com",
                "report_url": "https://cloud.tencent.com/",
            },
            "yandex": {
                "name": "Yandex Cloud",
                "short": "Yandex",
                "abuse_contact": "abuse@yandex-team.ru",
                "security_contact": "security@yandex-team.ru",
                "report_url": "https://cloud.yandex.com/",
            },
            "huawei": {
                "name": "Huawei Cloud",
                "short": "Huawei",
                "abuse_contact": "abuse@huaweicloud.com",
                "security_contact": "security@huaweicloud.com",
                "report_url": "https://www.huaweicloud.com/",
            },
            "cloudflare": {
                "name": "Cloudflare",
                "short": "CF",
                "abuse_contact": "abuse@cloudflare.com",
                "security_contact": "security@cloudflare.com",
                "report_url": "https://www.cloudflare.com/abuse/",
            },
            "scaleway": {
                "name": "Scaleway",
                "short": "Scaleway",
                "abuse_contact": "abuse@scaleway.com",
                "security_contact": "security@scaleway.com",
                "report_url": "https://www.scaleway.com/",
            },
            "contabo": {
                "name": "Contabo",
                "short": "Contabo",
                "abuse_contact": "abuse@contabo.de",
                "security_contact": "support@contabo.com",
                "report_url": "https://contabo.com/",
            },
            "ionos": {
                "name": "IONOS",
                "short": "IONOS",
                "abuse_contact": "abuse@ionos.com",
                "security_contact": "security@ionos.com",
                "report_url": "https://www.ionos.com/",
            },
        }
        return provider_info.get(provider, {})
