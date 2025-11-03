# REX SCAN# REX SCAN



**REX SCAN** is a comprehensive network reconnaissance and vulnerability scanner designed for penetration testers and security professionals. It orchestrates multiple security tools (nmap, DNS enumeration, directory scanning, exploit searches) and produces detailed reports in multiple formats.**REX SCAN: Reconnaissance and Exploitation Scanner**



## FeaturesA comprehensive, modular penetration testing toolkit that automates reconnaissance, service enumeration, vulnerability detection, and exploitation research. Designed for professional security assessments with extensive reporting capabilities.



- **Automated Network Scanning**: Intelligent nmap integration with service detection## Features

- **DNS Enumeration**: Subdomain discovery and DNS record analysis

- **Directory Enumeration**: Web path discovery with multiple wordlist support### Core Capabilities

- **Vulnerability Correlation**: Automated exploit-db lookup and CVE matching- **Network Scanning**: Automated nmap integration with customizable timing and port ranges

- **Credential Testing**: Conservative credential checks (FTP anonymous, default passwords)- **Service Enumeration**: Targeted enumeration for SSH, SMB, HTTP, FTP, MySQL, and more

- **Advanced Web Analysis**: SSL certificate analysis, security header checks, technology detection- **DNS Enumeration**: Subdomain discovery with passive DNS lookups and zone transfer detection

- **Screenshot Capture**: Automated web service screenshot capture- **Directory Enumeration**: Web path discovery with multiple wordlists and extensions

- **Multi-Format Reports**: Text, JSON, and HTML reports with charts- **Advanced Web Analysis**: SSL/TLS analysis, security header checks, CMS detection, technology fingerprinting

- **Resume Capability**: Interrupt and resume long-running scans- **Vulnerability Correlation**: Automated CVE lookup and exploit-db integration

- **Target Flexibility**: Single IPs, CIDR ranges, IP ranges, hostname lists- **Credential Testing**: Conservative credential checking with common defaults

- **Screenshot Capture**: Automated web service screenshot capture with Playwright

## Requirements- **Multi-Target Support**: CIDR ranges, IP ranges, comma-separated targets, and file input



### System Tools (Required)### Reporting

- **nmap** - Network scanning- **Text Reports**: Detailed findings in human-readable format

- **searchsploit** (exploitdb) - Vulnerability/exploit lookup- **JSON Reports**: Machine-parsable output for integration

- **HTML Reports**: Rich interactive reports with charts and visualizations

### System Tools (Optional)- **Scan Comparison**: Diff two scans to identify changes

- **gobuster** - Directory enumeration (Python fallback available)

- **dig** - DNS enumeration (dnspython fallback available)### Advanced Features

- **Scan Profiles**: Pre-configured profiles (stealth, balanced, aggressive, quick, full)

### Python Requirements- **Rate Limiting**: Configurable request throttling to avoid detection

- Python 3.8 or higher- **Resume Capability**: Interrupt and resume long-running scans

- See `requirements.txt` for Python dependencies- **Modular Architecture**: Easy to extend with additional enumeration modules



## Installation## Installation



### 1. Clone Repository### Prerequisites



```bash**Required:**

git clone https://github.com/yourusername/rex_scan.git- Python 3.8 or higher

cd rex_scan- nmap 7.0 or higher

```

**Optional (for full functionality):**

### 2. Create Python Virtual Environment- searchsploit (exploit-db)

- gobuster (directory enumeration)

```bash- playwright (screenshot capture)

# Create virtual environment

python3 -m venv venv### Install Dependencies



# Activate virtual environment```bash

# On macOS/Linux:# Clone the repository

source venv/bin/activategit clone <repository-url>

# On Windows:cd rex_scan

# venv\Scripts\activate

```# Create virtual environment

python3 -m venv venv

### 3. Install Python Dependenciessource venv/bin/activate  # On Windows: venv\Scripts\activate



```bash# Install Python dependencies

# Install core dependenciespip install -r requirements.txt

pip install -r requirements.txt

# Install system tools (Ubuntu/Debian)

# For screenshot capture, install playwright browserssudo apt-get install nmap exploitdb gobuster

playwright install chromium

```# Install Playwright browsers (for screenshots)

playwright install chromium

### 4. Install System Tools```



Run the automated installer:## Quick Start



```bash### Interactive Mode

# On macOS/Linux:

bash install_tools.sh```bash

python -m rex_scan

# Or install manually:```

# macOS:

brew install nmap exploitdb gobuster bindThe tool will prompt for target, consent, and configuration options.



# Debian/Ubuntu:### Basic Scan

sudo apt-get install nmap exploitdb gobuster dnsutils

```bash

# RedHat/CentOS/Fedora:python -m rex_scan --target 192.168.1.100 --consent

sudo yum install nmap```

```

### Common Use Cases

### 5. Verify Installation

**Quick scan with top 1000 ports:**

```bash```bash

# Check system toolspython -m rex_scan --target example.com --profile quick --consent

nmap --version```

searchsploit --version

gobuster version  # optional**Full scan with all enumeration:**

dig -v           # optional```bash

python -m rex_scan --target 192.168.1.100 --profile full \

# Run REX SCAN help  --dns-wordlist auto --dir-wordlist auto \

python -m rex_scan --help  --screenshots --consent

``````



## Quick Start**Stealth scan:**

```bash

### Basic Scanpython -m rex_scan --target 10.0.0.5 --profile stealth --consent

```

```bash

python -m rex_scan --target 192.168.1.100 --consent**Scan CIDR range:**

``````bash

python -m rex_scan --target 192.168.1.0/24 --ports 80,443 --consent

### Scan with Custom Ports```



```bash**Custom nmap flags:**

python -m rex_scan --target 192.168.1.100 --ports 1-1000 --consent```bash

```python -m rex_scan --target 192.168.1.100 \

  --profile custom \

### Full Enumeration Scan  --nmap-flags "-sS -T5 -p- -A -v" \

  --consent

```bash```

python -m rex_scan \

  --target 192.168.1.100 \## Usage

  --ports 1-65535 \

  --dns-wordlist /path/to/subdomains.txt \### Target Specification

  --dir-wordlist /path/to/directories.txt \

  --screenshots \```bash

  --advanced-web \# Single IP

  --consent \--target 192.168.1.100

  --output ~/scans/target1

```# Hostname

--target example.com

### Scan Multiple Targets

# CIDR range

```bash--target 192.168.1.0/24

# CIDR notation

python -m rex_scan --target 192.168.1.0/24 --consent# IP range

--target 192.168.1.1-50

# IP range

python -m rex_scan --target 192.168.1.1-50 --consent# Comma-separated

--target 192.168.1.100,192.168.1.101

# File with targets (one per line)

python -m rex_scan --targets @targets.txt --consent# File input

--targets @targets.txt

# Comma-separated```

python -m rex_scan --target "192.168.1.100,192.168.1.200" --consent

```### Scan Profiles



### Resume Interrupted Scan- **stealth**: Slow, minimal intrusion (T1 timing)

- **balanced**: Default safe scanning (T3 timing)

```bash- **aggressive**: Fast, more intrusive (T4 timing)

# If scan was interrupted (Ctrl+C)- **quick**: Top 1000 ports only

python -m rex_scan --resume ~/scans/target1- **full**: All 65535 ports

```- **custom**: Use with --nmap-flags for full control



## Usage Examples### Enumeration Options



### Scan Profiles```bash

# DNS enumeration with wordlist

REX SCAN includes predefined scan profiles:--dns-wordlist /path/to/subdomains.txt

--dns-wordlist auto  # Use built-in wordlist

```bash

# Stealth scan (T1 timing, minimal probes)# Directory enumeration

python -m rex_scan --target 192.168.1.100 --profile stealth --consent--dir-wordlist /path/to/directories.txt

--dir-wordlist auto  # Use built-in wordlist

# Balanced scan (default, T3 timing)--dir-extensions php,asp,aspx,jsp

python -m rex_scan --target 192.168.1.100 --profile balanced --consent

# Advanced web enumeration

# Aggressive scan (T4 timing, comprehensive)--advanced-web

python -m rex_scan --target 192.168.1.100 --profile aggressive --consent

# Screenshot capture

# Quick scan (T5 timing, fast)--screenshots

python -m rex_scan --target 192.168.1.100 --profile quick --consent```



# Full scan (all 65535 ports)### Output Options

python -m rex_scan --target 192.168.1.100 --profile full --consent

``````bash

# Specify output directory

### Custom nmap Flags--output ~/scans/target1



```bash# Disable charts

python -m rex_scan \--no-charts

  --target 192.168.1.100 \

  --profile custom \# Disable screenshots

  --nmap-flags "-sS -T5 -p- -A -v" \--no-screenshots

  --consent```

```

### Rate Limiting

### DNS Enumeration Only

```bash

```bash# Requests per second

python -m rex_scan \--rate-limit 5

  --target example.com \

  --dns-wordlist /usr/share/wordlists/subdomains.txt \# Delay between requests (seconds)

  --no-vulns \--delay 2

  --no-creds \```

  --consent

```### Resume and Comparison



### Disable Specific Features```bash

# Resume interrupted scan

```bash--resume /path/to/scan/folder

python -m rex_scan \

  --target 192.168.1.100 \# Compare two scans

  --no-screenshots \--diff /path/to/scan1/report.json /path/to/scan2/report.json

  --no-charts \```

  --no-creds \

  --no-vulns \### Full Options

  --consent

``````bash

python -m rex_scan --help

## Command Line Options```



```## Output Structure

Targeting:

  --target TARGET        Single IP, hostname, or CIDR (e.g., 192.168.1.0/24)```

  --targets FILE         File with targets (one per line)scan_folder/

  --ports PORTS          Port specification (default: 1-1000)├── INDIVIDUAL/              # Individual tool outputs

│   ├── nmap.xml            # Raw nmap output

Scan Profiles:│   ├── nmap_parsed.json    # Parsed nmap data

  --profile PROFILE      stealth, balanced, aggressive, quick, full, custom│   ├── dns_enum.json       # DNS enumeration results

│   ├── dir_enum.json       # Directory enumeration results

Enumeration:│   ├── advanced_web_enum.json  # Advanced web analysis

  --dns-wordlist FILE    DNS subdomain wordlist (or 'auto', 'none')│   ├── searchsploit.txt    # Exploit search results

  --dir-wordlist FILE    Directory enumeration wordlist (or 'auto', 'none')│   ├── vulnerabilities.json # CVE correlations

  --advanced-web         Enable advanced web enumeration (SSL, headers, tech)│   └── credentials.json    # Credential check results

  --screenshots          Capture web service screenshots├── REX_REPORTS/            # Final reports

│   ├── report.txt          # Human-readable report

Nmap Options:│   ├── report.json         # Machine-parsable report

  --nmap-timing T        Nmap timing template (0-5)│   ├── report.html         # Interactive HTML report

  --nmap-flags FLAGS     Custom nmap flags (requires --profile custom)│   └── charts/             # Visualization charts

└── screenshots/            # Web service screenshots

Rate Limiting:    ├── http_192.168.1.100_80.png

  --rate-limit N         Maximum requests per second (default: 10)    └── https_192.168.1.100_443.png

  --delay N              Delay between requests in seconds```



Output:## Testing

  --output DIR           Output directory (default: ~/Desktop/rex_scan_<timestamp>)

  --no-charts            Disable chart generation### Run Test Suite

  --quiet                Minimal output

```bash

Control:# All tests

  --consent              Skip authorization promptpython -m pytest tests/

  --yes                  Answer yes to all prompts

  --no-creds             Disable credential checks# Specific test

  --no-vulns             Disable vulnerability correlationpython -m pytest tests/test_nmap_parser.py

  --continue-on-error    Continue scan even if errors occur

# With coverage

Resume:python -m pytest --cov=rex_scan tests/

  --resume DIR           Resume interrupted scan from directory

# Metasploitable validation

Comparison:python tests/test_metasploitable.py

  --diff SCAN1 SCAN2     Compare two scan reports

```# Advanced features test

python tests/test_advanced_features_v2.py

## Output Structure

# Resume functionality test

Each scan creates an organized output directory:sudo python tests/test_resume_feature.py

```

```

scan_output/## Security and Ethics

├── REX_REPORTS/

│   ├── report.txt          # Human-readable text report**IMPORTANT:** Only use REX SCAN on systems you own or have explicit written authorization to test.

│   ├── report.json         # Machine-readable JSON

│   ├── report.html         # Interactive HTML dashboard- Unauthorized port scanning may be illegal in your jurisdiction

│   └── charts/             # Visualization charts (if enabled)- Credential testing may trigger account lockouts or alerts

│       ├── port_distribution.png- Directory enumeration can generate significant traffic

│       ├── service_breakdown.png- Always obtain proper authorization before testing

│       └── vulnerability_severity.png

├── INDIVIDUAL/The tool requires explicit consent (--consent flag or interactive confirmation) before running potentially intrusive checks.

│   ├── nmap.xml            # Raw nmap output

│   ├── nmap_parsed.json    # Parsed nmap data## Architecture

│   ├── dns_enum.json       # DNS enumeration results

│   ├── dir_enum.json       # Directory scan resultsREX SCAN is built with a modular architecture:

│   ├── advanced_web_enum.json  # Web analysis results

│   ├── credentials.json    # Credential check results- **Core Engine**: Orchestrates scan workflow and manages state

│   ├── vulnerabilities.json    # CVE/exploit matches- **Enumeration Modules**: Pluggable modules for different services

│   └── searchsploit.txt    # Exploit-db search output- **Parser Layer**: Standardizes output from various tools

└── SCREENSHOTS/            # Web service screenshots (if enabled)- **Reporting Engine**: Generates multiple output formats

    ├── http_192.168.1.100_80.png- **Rate Limiter**: Controls request frequency

    └── https_192.168.1.100_443.png- **State Manager**: Enables scan resume capability

```

## Troubleshooting

## Testing

### Common Issues

REX SCAN includes comprehensive test suites:

**"nmap not found"**

```bash```bash

# Run all tests# Install nmap

python tests/test_metasploitable.pysudo apt-get install nmap  # Debian/Ubuntu

python tests/test_resume_feature.pybrew install nmap           # macOS

``````



## Security Considerations**"Permission denied"**

```bash

### Authorization# SYN scans require root

sudo python -m rex_scan --target 192.168.1.100 --consent

**IMPORTANT**: Only scan systems you own or have explicit written authorization to test.```



- REX SCAN will prompt for authorization unless `--consent` is used**"No module named 'rex_scan'"**

- Credential testing is enabled by default (use `--no-creds` to disable)```bash

- Some scan profiles are more intrusive than others# Ensure you're in the project directory and virtual environment is activated

- Always review applicable laws and regulationssource venv/bin/activate

```

### Network Impact

**Screenshots not working**

- Aggressive scans may trigger IDS/IPS systems```bash

- Rate limiting is enabled by default (10 req/sec)# Install Playwright browsers

- Use `--profile stealth` for less noisy scansplaywright install chromium

- Consider `--delay` for rate-sensitive targets```



### Data Handling## Contributing



- Scan results may contain sensitive informationContributions are welcome! Please:

- Output directories should be protected appropriately

- HTML reports are self-contained (safe to share filtered)1. Fork the repository

- JSON reports include raw data (review before sharing)2. Create a feature branch

3. Add tests for new functionality

## Troubleshooting4. Ensure all tests pass

5. Submit a pull request

### Common Issues

## Documentation

**"nmap not found"**

```bash- **FEATURES.md**: Detailed feature documentation

# Install nmap- **QUICK_REFERENCE.md**: Command reference and examples

# macOS: brew install nmap- **COMPREHENSIVE_AUDIT_REPORT.md**: Testing and validation report

# Linux: sudo apt-get install nmap- **RESUME_FUNCTIONALITY_TEST_REPORT.md**: Resume capability testing

```

## License

**"searchsploit not found"**

```bashThis project is provided under the MIT License. See LICENSE file for details.

# Install exploitdb

# macOS: brew install exploitdb## Disclaimer

# Linux: sudo apt-get install exploitdb

```This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for misuse or damage caused by this program. Always ensure you have proper authorization before conducting security assessments.


**"Screenshots failing"**
```bash
# Install playwright browsers
playwright install chromium
```

**"Permission denied" errors**
```bash
# Some scans require sudo (SYN scan, etc.)
sudo python -m rex_scan --target 192.168.1.100 --consent
```

**"Scan very slow"**
```bash
# Use faster timing profile
python -m rex_scan --target 192.168.1.100 --profile quick --consent

# Or reduce port range
python -m rex_scan --target 192.168.1.100 --ports 1-100 --consent
```

### Debug Mode

For verbose output and debugging:

```bash
python -m rex_scan --target 192.168.1.100 --consent -v
```

## Development

### Project Structure

```
rex_scan/
├── rex_scan/              # Main package
│   ├── __init__.py
│   ├── __main__.py       # Entry point
│   ├── cli.py            # Command-line interface
│   ├── config.py         # Configuration
│   ├── nmap_runner.py    # Nmap execution
│   ├── nmap_parser.py    # Nmap XML parsing
│   ├── target_parser.py  # Target parsing (CIDR, ranges)
│   ├── dns_enum.py       # DNS enumeration
│   ├── dir_enum.py       # Directory scanning
│   ├── advanced_web_enum.py  # Web analysis
│   ├── screenshot.py     # Screenshot capture
│   ├── exploitdb.py      # Exploit-db integration
│   ├── vuln_correlator.py    # CVE matching
│   ├── creds.py          # Credential testing
│   ├── report.py         # Report generation
│   ├── chart_generator.py    # Visualization
│   ├── diff_scanner.py   # Scan comparison
│   ├── scan_state.py     # Resume capability
│   └── templates/        # Report templates
│       └── report.html.j2
├── tests/                # Test suite
│   ├── test_metasploitable.py
│   └── test_resume_feature.py
├── requirements.txt      # Python dependencies
├── setup.py             # Package setup
├── install_tools.sh     # System tools installer
└── README.md            # This file
```

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Disclaimer

This tool is designed for authorized security testing and research purposes only. The authors and contributors are not responsible for misuse or damage caused by this tool. Users must ensure they have proper authorization before scanning any systems.

## Acknowledgments

- **nmap** - Network scanning foundation
- **exploit-db** - Vulnerability database
- **gobuster** - Directory enumeration
- All contributors and security researchers

---

**Version**: 2.0.0  
**Status**: Production Ready  
**Last Updated**: November 2025
