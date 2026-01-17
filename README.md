[![GitHub release](https://img.shields.io/github/release/Z4ck404/elasticsearch-finder.svg?color=orange&style=popout)](https://github.com/Z4ck404/elasticsearch-finder/releases)
[![CI](https://github.com/Z4ck404/elasticsearch-finder/actions/workflows/ci.yml/badge.svg)](https://github.com/Z4ck404/elasticsearch-finder/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)


# elasticsearch-finder
A powerful tool to find and analyze open Elasticsearch instances for bug bounty purposes.

```
            ___________       ___________   ______  __________
           / ____/ ___/      / ____/  _/ | / / __ \/ ____/ __ \
          / __/  \__ \______/ /_   / //  |/ / / / / __/ / /_/ /
         / /___ ___/ /_____/ __/ _/ // /|  / /_/ / /___/ _, _/
        /_____//____/     /_/   /___/_/ |_/_____/_____/_/ |_|

```

## Features

- Search for open Elasticsearch instances via Shodan and BinaryEdge
- **Cloud Provider Detection** - Identify AWS, GCP, Azure, OVH, DigitalOcean, Hetzner, Tencent, Yandex, Cloudflare and 20+ more
- **Advanced Data Leak Scanner** - Detect personal data across 50+ patterns (emails, SSNs, credit cards, passwords, API keys, medical records, etc.)
- **Compliance Framework Detection** - Identify GDPR, HIPAA, PCI-DSS, CCPA violations
- **Risk Scoring** - Automatic risk assessment with MITRE ATT&CK mapping and actionable recommendations
- **Deep Scanning** - Direct Elasticsearch querying to analyze index schemas and sample data
- **Credential Detection** - Find exposed API keys, JWT tokens, AWS keys, GitHub tokens, private keys
- Export results to text, Excel, and JSON files
- Filter by country code, cloud provider, or minimum risk level
- Pagination support

## Installation

### Requirements
- Python 3.9+
- [Shodan](https://www.shodan.io/) API Key
- [BinaryEdge](https://www.binaryedge.io/) API Key

### Install from source

```bash
# Clone the repository
git clone https://github.com/Z4ck404/elasticsearch-finder.git
cd elasticsearch-finder

# Install with uv (recommended - faster)
uv sync

# Or install with pip
pip install -e .

# For development (with uv)
uv sync --dev

# For development (with pip)
pip install -e ".[dev]"
```

### Docker Installation (Recommended)

The easiest way to run elasticsearch-finder is with Docker:

```bash
# Pull from GitHub Container Registry
docker pull ghcr.io/z4ck404/elasticsearch-finder:latest

# Or build locally
docker build -t elasticsearch-finder .
```

### Configure API Keys

Set your API keys as environment variables:

```bash
export SHODAN_API_KEY="your_shodan_api_key"
export BINARYEDGE_API_KEY="your_binaryedge_api_key"
```

## Usage

### Command Line

```bash
# Basic usage with Shodan
esf -s

# Basic usage with BinaryEdge
esf -b

# Run with both sources
esf -s -b

# Enable analysis mode (cloud detection + PII scanning + risk scoring)
esf -s -b --analyze

# Deep scan mode (queries ES instances directly - use responsibly!)
esf -s --analyze --deep-scan

# Filter by cloud provider (aws, gcp, azure, ovh, digitalocean, etc.)
esf -s -b --analyze --provider aws

# Only show high-risk results with PII
esf -s -b --analyze --min-risk high --pii-only

# Export to JSON for further processing
esf -s -b --analyze --json -o results

# Filter by country and specify output file
esf -s -b -c US -o results

# With pagination
esf -s -b -f 1 -l 10
```

### Docker Usage

```bash
# Run with Docker (showing help)
docker run --rm ghcr.io/z4ck404/elasticsearch-finder:latest

# Run with API keys
docker run --rm \
  -e SHODAN_API_KEY="your_key" \
  -e BINARYEDGE_API_KEY="your_key" \
  ghcr.io/z4ck404/elasticsearch-finder:latest \
  -s -b --analyze

# Save output to local directory
docker run --rm \
  -e SHODAN_API_KEY="your_key" \
  -v $(pwd)/output:/app/output \
  ghcr.io/z4ck404/elasticsearch-finder:latest \
  -s --analyze -o results

# Using docker-compose (recommended for repeated use)
# First, copy .env.example to .env and add your API keys
cp .env.example .env
# Edit .env with your API keys

# Then run
docker-compose run --rm esf -s -b --analyze -o results
```

### Command Line Options

| Option | Description |
|--------|-------------|
| `-s, --shodan` | Use Shodan as data source |
| `-b, --be` | Use BinaryEdge as data source |
| `-c, --country` | Filter by country code (e.g., US, FR, DE) |
| `-o, --output` | Output filename (without extension) |
| `-f, --first` | First page for pagination (default: 1) |
| `-l, --last` | Last page for pagination (default: 30) |
| `-k, --keyword` | Add keyword to search |
| `-v, --version` | Show version |
| `--analyze` | Enable deep analysis (cloud provider, PII, risk scoring) |
| `--deep-scan` | Query ES instances directly for detailed analysis |
| `--provider` | Filter by cloud provider (aws, gcp, azure, ovh, etc.) |
| `--min-risk` | Minimum risk level (informational, low, medium, high, critical) |
| `--pii-only` | Only show results with detected PII |
| `--json` | Output results in JSON format |

## Analysis Features

### Cloud Provider Detection

Automatically detects hosting on 20+ cloud providers:

**Major Cloud Providers:**
- **AWS** (Amazon Web Services)
- **GCP** (Google Cloud Platform)
- **Azure** (Microsoft Azure)
- **Alibaba Cloud**
- **Tencent Cloud**
- **Oracle Cloud**
- **IBM Cloud**
- **Huawei Cloud**

**VPS/Hosting Providers:**
- **DigitalOcean**
- **OVH / OVHcloud**
- **Linode (Akamai)**
- **Vultr**
- **Hetzner**
- **Scaleway**
- **Contabo**
- **IONOS**
- **Kamatera**
- **Hostinger**

**CDN/Edge Providers:**
- **Cloudflare**
- **Fastly**

Detection methods include:
- IP range matching
- Hostname/reverse DNS analysis
- ASN detection
- Organization name matching

Includes abuse contact information for responsible disclosure.

### Advanced Data Leak Scanner

The new `DataLeakScanner` provides comprehensive data leak detection with 50+ patterns:

**Personal Identifiable Information (PII):**
- Email addresses (with domain categorization)
- Phone numbers (US, UK, international formats)
- Social Security Numbers (SSN)
- National ID numbers (UK NINO, French INSEE, German Tax ID)
- Passport numbers
- Driver's license numbers
- Dates of birth
- Physical addresses and postal codes
- IP addresses and MAC addresses

**Financial Data:**
- Credit card numbers (Visa, Mastercard, Amex, Discover)
- Bank account numbers (IBAN, routing numbers)
- Cryptocurrency addresses (Bitcoin, Ethereum)

**Authentication & Credentials:**
- Passwords and password hashes (MD5, SHA-256, BCrypt)
- API keys and secrets
- AWS Access Keys and Secret Keys
- GitHub Personal Access Tokens
- Google API Keys
- JWT tokens
- Private keys (RSA, EC, DSA)

**Healthcare Data (HIPAA):**
- Medical Record Numbers (MRN)
- NPI numbers
- ICD-10 diagnosis codes
- Prescription/medication information

**Behavioral/Tracking Data:**
- User agent strings
- Session IDs
- Geolocation coordinates
- Tracking IDs

### Compliance Framework Detection

Automatically identifies potential violations of:
- **GDPR** (EU General Data Protection Regulation)
- **CCPA** (California Consumer Privacy Act)
- **HIPAA** (Health Insurance Portability and Accountability Act)
- **PCI-DSS** (Payment Card Industry Data Security Standard)
- **SOX** (Sarbanes-Oxley Act)
- **FERPA** (Family Educational Rights and Privacy Act)

Provides compliance-specific recommendations for breach notification.

### PII Scanner

Detects sensitive personal data including:
- Email addresses
- Phone numbers (US and international)
- Social Security Numbers (SSN)
- Credit card numbers
- Passwords and API keys
- AWS credentials
- JWT tokens
- Medical record identifiers
- Bank account numbers (IBAN)
- Physical addresses
- And more...

### Risk Scoring

Enhanced risk scoring system that calculates risk based on:
- **Data size** (larger datasets = higher risk)
- **Index sensitivity** (user data, financial, medical, auth)
- **PII detection results** (type and volume of personal data)
- **Credential exposure** (API keys, tokens, passwords)
- **Cloud provider exposure** (production vs development indicators)
- **Compliance risk** (GDPR, HIPAA, PCI-DSS impact)
- **Number of nodes** (cluster size/importance)
- **Accessibility** (public access without authentication)

Risk levels: `informational`, `low`, `medium`, `high`, `critical`

**Threat Indicators:**
- MITRE ATT&CK technique mapping
- Severity-based prioritization
- Actionable remediation guidance

**Executive Summary Reports:**
- Weighted component breakdown
- Compliance framework impact
- Cloud provider abuse contacts
- Estimated records affected

## Programmatic Usage

You can also use the analyzers directly in your Python code:

```python
from elasticsearch_finder.analyzers import (
    DataLeakScanner,
    CloudProviderAnalyzer,
    RiskScorer,
    ElasticsearchScanner
)

# Initialize scanners
leak_scanner = DataLeakScanner()
cloud_analyzer = CloudProviderAnalyzer()
risk_scorer = RiskScorer()
es_scanner = ElasticsearchScanner()

# Scan text for personal data
text = "Contact: john.doe@company.com, SSN: 123-45-6789"
result = leak_scanner.scan_text(text)
print(f"Found PII: {result['found']}")
print(f"Compliance impact: {result['compliance_impact']}")

# Detect emails with domain analysis
email_result = leak_scanner.detect_emails(text)
print(f"Corporate domains: {email_result['corporate_domains']}")

# Detect credentials
creds = leak_scanner.detect_credentials("AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE")
print(f"Credentials found: {creds['credentials_found']}")

# Analyze cloud provider from IP/hostname
cloud_result = cloud_analyzer.analyze(
    ip="54.239.28.85",
    org="Amazon.com",
    hostname="ec2-54-239-28-85.compute-1.amazonaws.com"
)
print(f"Provider: {cloud_result['provider']}")
print(f"Confidence: {cloud_result['confidence']}")

# Get provider abuse contact
provider_info = cloud_analyzer.get_provider_info("aws")
print(f"Abuse contact: {provider_info['abuse_contact']}")

# Calculate risk score
risk_result = risk_scorer.calculate_risk_score(
    cluster_size_bytes=1024*1024*1024,  # 1GB
    pii_analysis=result,
    cloud_analysis=cloud_result,
    is_accessible=True
)
print(f"Risk level: {risk_result['risk_level']}")
print(f"Score: {risk_result['total_score']}")

# Generate executive summary
summary = risk_scorer.generate_executive_summary(risk_result, cloud_result)
print(summary)

# Assess compliance risk
compliance = leak_scanner.assess_compliance_risk(result)
print(f"GDPR impact: {compliance['gdpr_impact']}")
print(f"Recommendations: {compliance['recommendations']}")
```

## Output

Results are saved to:
- Text file: `<output>.txt`
- Excel file: `<output>.xlsx`

Each entry includes:
- Host IP and port
- Country
- Cluster name
- Number of nodes
- Cluster size
- Index information

## Development

### Running Tests

```bash
# Install development dependencies (with uv)
uv sync --dev

# Run tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=elasticsearch_finder

# Or with pip
pip install -e ".[dev]"
pytest
```

### Linting

```bash
# Run linter (with uv)
uv run ruff check src/ tests/

# Format code
uv run ruff format src/ tests/

# Or with pip
ruff check src/ tests/
ruff format src/ tests/
```

## Legacy Usage

For backward compatibility, the original `esf.py` script is still available:

```bash
python esf.py -s -b -o output.txt
```

## Elasticsearch Security
- There is an open source plugin available with a free/community edition called [Search Guard](https://github.com/floragunncom/search-guard)

## Credits
- Inspired from [Kibanarec](https://github.com/Lekssays/kibanarec) by [Ahmed Lessays](https://github.com/Lekssays) and from [LeakLocker](https://github.com/woj-ciech/LeakLooker) by [woj-ciech](https://github.com/woj-ciech).
- Some parts are taken from [Hostname](https://github.com/SpiderLabs/HostHunter) by [SpiderLabs](https://github.com/SpiderLabs)

## License

MIT License - see [LICENSE](LICENSE) for details.


