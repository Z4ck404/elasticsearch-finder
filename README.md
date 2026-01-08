[![GitHub release](https://img.shields.io/github/release/Z4ck404/elasticsearch-finder.svg?color=orange&style=popout)](https://github.com/Z4ck404/elasticsearch-finder/releases)
[![CI](https://github.com/Z4ck404/elasticsearch-finder/actions/workflows/ci.yml/badge.svg)](https://github.com/Z4ck404/elasticsearch-finder/actions/workflows/ci.yml)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)


# elasticsearch-finder
A tool to find open instances of Elasticsearch for bug bounty purposes.

```
            ___________       ___________   ______  __________
           / ____/ ___/      / ____/  _/ | / / __ \/ ____/ __ \
          / __/  \__ \______/ /_   / //  |/ / / / / __/ / /_/ /
         / /___ ___/ /_____/ __/ _/ // /|  / /_/ / /___/ _, _/
        /_____//____/     /_/   /___/_/ |_/_____/_____/_/ |_|

```

## Features

- Search for open Elasticsearch instances via Shodan and BinaryEdge
- Export results to text and Excel files
- Filter by country code
- Pagination support
- Proper configuration via environment variables

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

# Install the package
pip install -e .

# Or for development
pip install -e ".[dev]"
```

### Configure API Keys

Set your API keys as environment variables:

```bash
export SHODAN_API_KEY="your_shodan_api_key"
export BINARYEDGE_API_KEY="your_binaryedge_api_key"
```

## Usage

```bash
# Run with Shodan
esf -s

# Run with BinaryEdge
esf -b

# Run with both sources
esf -s -b

# Filter by country and specify output file
esf -s -b -c US -o results

# With pagination
esf -s -b -f 1 -l 10
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
# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=elasticsearch_finder
```

### Linting

```bash
# Run linter
ruff check src/ tests/

# Format code
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


