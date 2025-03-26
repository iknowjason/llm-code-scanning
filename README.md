# LLM-Powered Code Security Scanning
My research and code on being able to use an LLM to automate finding vulnerabiltiies in source code.

## Python PoC
The ```script``` directory contains the evolving python PoC for security scanning.

- Supports both OpenAI and Anthropic APIs
- Can scan individual files or entire directories
- Detects vulnerabilities in multiple programming languages
- Provides detailed information about each vulnerability
- Generates reports in JSON or Markdown format

## Github Actions Workflow Automation
The ```workflows``` directory contains the Github Actions workflow to integrate into automation.

- Runs automatically on pushes, pull requests, and on a weekly schedule
- Scans only changed files in pull requests for efficiency
- Performs a full scan in scheduled runs or pushes to main
- Creates GitHub issues for detected vulnerabilities
- Uploads scan results as workflow artifacts

## Vulnerable Code Examples
The ```vulnerable-code``` directory contains example vulnerable code you can scan to test findings.  For now it is a vulnerable python app but I will add more languages as soon as possible.

