# Enterprise Security Assessment Toolkit

![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Active%20Development-orange)
![Security](https://img.shields.io/badge/Focus-Defensive%20Security-red)

Enterprise Security Assessment Toolkit is a modular defensive cybersecurity CLI designed for internal security assessments, web security baselines, host exposure analysis, SSH log triage, risk scoring and compliance-oriented reporting.

The project is focused on **Blue Team**, **SOC triage**, **internal audit**, **security engineering** and **authorized defensive assessments**.

> This tool does not exploit vulnerabilities. It performs safe checks, analyzes exposed services, reviews web security posture and generates technical findings with recommendations.

---

## Table of Contents

- [Overview](#overview)
- [Key Capabilities](#key-capabilities)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
  - [Web Security Scan](#web-security-scan)
  - [Host Exposure Scan](#host-exposure-scan)
  - [SSH Log Analysis](#ssh-log-analysis)
  - [YAML Configuration](#yaml-configuration)
- [Reporting](#reporting)
- [Risk Scoring](#risk-scoring)
- [Compliance Intelligence](#compliance-intelligence)
- [Project Structure](#project-structure)
- [Examples](#examples)
- [Testing](#testing)
- [GitHub Actions](#github-actions)
- [Security Notice](#security-notice)
- [Limitations](#limitations)
- [Roadmap](#roadmap)
- [Development Workflow](#development-workflow)
- [Author](#author)
- [License](#license)

---

## Overview

Enterprise Security Assessment Toolkit provides a unified CLI for performing lightweight but structured cybersecurity assessments.

It currently supports:

- Web security checks
- TLS certificate intelligence
- HTTP security headers analysis
- Cookie security analysis
- Host exposure scanning
- TCP service risk classification
- Banner grabbing
- SSH authentication log analysis
- Brute-force detection
- MITRE ATT&CK mapping
- OWASP ASVS mapping
- NIST CSF mapping
- Markdown, JSON and CSV reporting
- YAML-based assessment configuration
- Automated testing with pytest
- GitHub Actions CI workflow

The goal is to provide a professional, modular and extensible toolkit that can be used as a portfolio-grade cybersecurity project and as a foundation for enterprise-style defensive security automation.

---

## Key Capabilities

### Web Security Baseline

The web scanner performs defensive checks against authorized web targets.

Current checks include:

- HTTPS usage validation
- TLS certificate metadata collection
- TLS certificate expiration analysis
- HTTP security headers review
- Cookie security flags review
- Redirect security checks
- Risk scoring
- Report generation

Example findings:

- Missing `Content-Security-Policy`
- Missing `Strict-Transport-Security`
- Missing `X-Frame-Options`
- Missing `Referrer-Policy`
- Cookie missing `HttpOnly`
- Cookie missing `Secure`
- Cookie missing `SameSite`
- TLS certificate expires soon
- TLS certificate validation failed

---

### TLS Certificate Intelligence

The TLS module collects and evaluates certificate metadata.

It can identify:

- Certificate issuer
- Certificate subject
- Serial number
- Validity period
- Expiration date
- Days remaining
- Signature algorithm
- Expired certificate
- Certificate close to expiration
- TLS validation failures

Example finding:

```text
WEB-TLS-006 - TLS certificate metadata collected


Host Exposure Analysis

The host exposure scanner performs safe TCP checks against authorized hosts.

It supports:

Common port scanning
Custom port lists
Port ranges
Open service detection
Service risk classification
Banner grabbing
MITRE ATT&CK mapping

Common ports include:

21    FTP
22    SSH
23    Telnet
25    SMTP
53    DNS
80    HTTP
110   POP3
143   IMAP
389   LDAP
443   HTTPS
445   SMB
1433  Microsoft SQL Server
1521  Oracle Database
3306  MySQL/MariaDB
3389  RDP
5432  PostgreSQL
6379  Redis
9200  Elasticsearch

Example findings:

HOST-PORT-445  Open SMB service detected on port 445
HOST-PORT-3389 Open RDP service detected on port 3389
HOST-PORT-6379 Open Redis service detected on port 6379
LogGuard SSH Analysis

LogGuard analyzes Linux SSH authentication logs and detects suspicious authentication patterns.

Current detections include:

Multiple failed SSH login attempts
Attempts against invalid users
Root login attempts
Source IP aggregation
Targeted username aggregation
MITRE ATT&CK T1110 mapping

Example findings:

LOG-SSH-001 Multiple failed SSH login attempts detected
LOG-SSH-002 Multiple SSH attempts against invalid users
LOG-SSH-003 SSH root login attempts detected
Architecture

The toolkit follows a modular architecture.

CLI
│
├── Web Security Scanner
│   ├── Headers analysis
│   ├── Cookie analysis
│   ├── TLS certificate analysis
│   └── Redirect checks
│
├── Host Exposure Scanner
│   ├── TCP port scanning
│   ├── Banner grabbing
│   └── Service risk classification
│
├── LogGuard
│   ├── Linux auth.log parser
│   ├── SSH brute-force detector
│   ├── Invalid user detector
│   └── Root login detector
│
├── Compliance Intelligence
│   ├── MITRE ATT&CK mapping
│   ├── OWASP ASVS mapping
│   └── NIST CSF mapping
│
├── Risk Engine
│   ├── Severity weights
│   ├── Numerical risk score
│   └── Maximum severity classification
│
└── Reporting
    ├── Console output
    ├── Markdown reports
    ├── JSON reports
    └── CSV reports
Installation
Requirements
Python 3.11 or higher
Git
PowerShell, Windows Terminal or any terminal
VS Code recommended
Clone the repository
git clone https://github.com/moulguir/enterprise-security-assessment-toolkit.git
cd enterprise-security-assessment-toolkit
Create a virtual environment
Windows PowerShell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
Linux / macOS
python -m venv .venv
source .venv/bin/activate
Install dependencies
pip install -r requirements.txt

For local development mode:

pip install -e .
Usage

The toolkit can be executed directly with Python:

python -m sec_assess.cli --help

If installed in editable mode, it can also be executed as:

sec-assess --help
Web Security Scan

Run a basic web security scan:

python -m sec_assess.cli scan web --url https://example.com

Generate a Markdown report:

python -m sec_assess.cli scan web --url https://example.com --format markdown

Generate a JSON report:

python -m sec_assess.cli scan web --url https://example.com --format json

Generate a CSV report:

python -m sec_assess.cli scan web --url https://example.com --format csv

Example output:

╭───────── Security Assessment ──────────╮
│ Enterprise Security Assessment Toolkit │
│ Target: https://example.com            │
│ Risk Score: 89/100                     │
│ Overall Risk: MEDIUM                   │
╰────────────────────────────────────────╯

Summary by Severity
┏━━━━━━━━━━┳━━━━━━━┓
┃ Severity ┃ Count ┃
┡━━━━━━━━━━╇━━━━━━━┩
│ INFO     │ 1     │
│ LOW      │ 1     │
│ MEDIUM   │ 1     │
│ HIGH     │ 0     │
│ CRITICAL │ 0     │
└──────────┴───────┘
Host Exposure Scan

Run a safe host exposure scan against localhost:

python -m sec_assess.cli scan host --target 127.0.0.1 --ports common

Scan selected ports:

python -m sec_assess.cli scan host --target 127.0.0.1 --ports 80,443,445,3389

Scan a public domain with basic ports:

python -m sec_assess.cli scan host --target example.com --ports 80,443

Generate a host exposure report:

python -m sec_assess.cli scan host --target example.com --ports 80,443 --format markdown

Disable banner grabbing:

python -m sec_assess.cli scan host --target example.com --ports 80,443 --no-banner

Example output:

HOST-PORT-443  Open HTTPS service detected on port 443
HOST-PORT-445  Open SMB service detected on port 445
SSH Log Analysis

Analyze a Linux SSH authentication log:

python -m sec_assess.cli analyze logs --file examples/sample_logs/auth.log

Use a custom threshold:

python -m sec_assess.cli analyze logs --file examples/sample_logs/auth.log --threshold 3

Generate a Markdown report:

python -m sec_assess.cli analyze logs --file examples/sample_logs/auth.log --format markdown

Generate JSON:

python -m sec_assess.cli analyze logs --file examples/sample_logs/auth.log --format json

Example detected patterns:

LOG-SSH-001 Multiple failed SSH login attempts detected
LOG-SSH-002 Multiple SSH attempts against invalid users
LOG-SSH-003 SSH root login attempts detected
YAML Configuration

The toolkit supports YAML-based assessment configuration.

Example file:

target:
  name: egela-ehu
  url: https://egela.ehu.eus

scan:
  type: web
  timeout: 10

report:
  format: markdown
  output_dir: reports

risk:
  fail_on_high: false

Run the assessment:

python -m sec_assess.cli run --config examples/configs/web_scan.yml

Supported report formats:

console
markdown
json
csv

The fail_on_high option can be used in automation pipelines to return a failing exit code when the calculated risk level is HIGH or CRITICAL.

Reporting

The toolkit supports multiple output formats.

Console

Useful for interactive usage.

python -m sec_assess.cli scan web --url https://example.com
Markdown

Useful for technical documentation and audit reports.

python -m sec_assess.cli scan web --url https://example.com --format markdown
JSON

Useful for automation and integrations.

python -m sec_assess.cli scan web --url https://example.com --format json
CSV

Useful for Excel, Power BI, audit evidence and reporting workflows.

python -m sec_assess.cli scan web --url https://example.com --format csv

Reports are generated in the reports/ directory by default.

Risk Scoring

Each finding has a severity level:

INFO
LOW
MEDIUM
HIGH
CRITICAL

Severity weights are used to calculate a numerical security score from 0 to 100.

INFO     = 0
LOW      = 3
MEDIUM   = 8
HIGH     = 15
CRITICAL = 25

The global risk classification also considers the highest finding severity.

Example:

Risk Score: 85/100
Overall Risk: HIGH

This prevents a target with a HIGH finding from being shown as low risk only because the numerical score remains high.

Compliance Intelligence

The toolkit enriches findings with security framework mappings when available.

Supported frameworks:

MITRE ATT&CK
OWASP ASVS
NIST Cybersecurity Framework

Examples:

Finding	Framework Mapping
LOG-SSH-001	MITRE ATT&CK T1110 - Brute Force
HOST-PORT-445	MITRE ATT&CK T1046 - Network Service Discovery
WEB-HEADER-002	OWASP ASVS HTTP Security Headers
WEB-COOKIE-001	OWASP ASVS Session Management
LOG-SSH-003	NIST CSF Detect / Adverse Event Analysis

Compliance metadata is included in Markdown, JSON and CSV reports.

Project Structure
enterprise-security-assessment-toolkit/
│
├── sec_assess/
│   ├── cli.py
│   ├── config.py
│   │
│   ├── core/
│   │   ├── scanner.py
│   │   ├── finding.py
│   │   ├── severity.py
│   │   └── risk_engine.py
│   │
│   ├── modules/
│   │   ├── web_security/
│   │   │   ├── headers.py
│   │   │   ├── cookies.py
│   │   │   ├── tls.py
│   │   │   ├── redirects.py
│   │   │   └── web_scanner.py
│   │   │
│   │   ├── host_exposure/
│   │   │   ├── port_scan.py
│   │   │   ├── banner_grab.py
│   │   │   ├── service_detection.py
│   │   │   └── host_scanner.py
│   │   │
│   │   ├── logguard/
│   │   │   ├── parsers/
│   │   │   ├── detectors/
│   │   │   └── log_scanner.py
│   │   │
│   │   └── compliance/
│   │       ├── mitre_attack.py
│   │       ├── owasp_asvs.py
│   │       ├── nist_csf.py
│   │       └── mapper.py
│   │
│   ├── reporting/
│   │   ├── console_report.py
│   │   ├── markdown_report.py
│   │   ├── json_report.py
│   │   ├── csv_report.py
│   │   └── templates/
│   │
│   ├── storage/
│   │   ├── database.py
│   │   └── models.py
│   │
│   └── utils/
│       └── url_utils.py
│
├── tests/
├── examples/
│   ├── sample_logs/
│   ├── sample_reports/
│   └── configs/
│
├── docs/
├── reports/
├── .github/
│   └── workflows/
│       └── tests.yml
│
├── README.md
├── requirements.txt
├── pyproject.toml
├── Dockerfile
├── docker-compose.yml
├── .gitignore
└── LICENSE
Examples
Web assessment
python -m sec_assess.cli scan web --url https://egela.ehu.eus --format markdown
Host exposure assessment
python -m sec_assess.cli scan host --target 127.0.0.1 --ports 80,443,445,3389
SSH log analysis
python -m sec_assess.cli analyze logs --file examples/sample_logs/auth.log
YAML-driven assessment
python -m sec_assess.cli run --config examples/configs/web_scan.yml
Testing

Run all tests:

python -m pytest

Example result:

collected 40+ items
tests/... PASSED

The project includes tests for:

Risk engine
URL utilities
HTTP security headers
Cookie analysis
YAML configuration
Reporting
Host exposure service classification
LogGuard SSH parsing and detection
Compliance mapping
GitHub Actions

The repository includes a GitHub Actions workflow that runs tests automatically on push and pull requests.

Workflow file:

.github/workflows/tests.yml
Security Notice

This project is intended for:

Defensive security
Internal security assessments
Blue Team analysis
SOC triage
Authorized testing
Educational cybersecurity labs
Security engineering portfolios

Do not use this tool against systems without explicit permission.

The toolkit does not perform exploitation, credential attacks, destructive actions or intrusive vulnerability exploitation.

Limitations

This project is not a replacement for enterprise vulnerability management platforms or SIEM products.

It is not currently:

A full SIEM
A full IDS/IPS
A full vulnerability scanner
A Nessus, Qualys or OpenVAS replacement
An EDR
A GRC platform

It is designed as a modular defensive assessment toolkit and portfolio-grade cybersecurity engineering project.

Roadmap

Planned improvements:

SQLite scan history
sec-assess history command
Finding database
Scan comparison
Multi-target inventory scanning
Correlation engine
HTML reporting
PDF reporting
Docker support
Better TLS configuration checks
Additional log parsers
Nginx/Apache log analysis
PCAP analysis
Baseline creation and drift detection
SARIF export for DevSecOps workflows
Integration-ready JSON schema
Development Workflow

Recommended workflow:

git status
python -m pytest
git add .
git commit -m "Describe the change"
git push

Run the CLI locally:

python -m sec_assess.cli --help

Run tests before every commit:

python -m pytest
Author

Mohamed Oulghirah

License

This project is released under the MIT License.