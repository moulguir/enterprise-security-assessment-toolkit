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