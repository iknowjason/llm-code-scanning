# LLM-Powered Code Security Scanning
My research and code on being able to use an LLM to automate finding vulnerabiltiies in source code.

The ```script``` directory contains the evolving python PoC for security scanning.

- Supports both OpenAI and Anthropic APIs
- Can scan individual files or entire directories
- Detects vulnerabilities in multiple programming languages
- Provides detailed information about each vulnerability
- Generates reports in JSON or Markdown format

The ```workflows``` directory contains the Github Actions workflow to integrate into automation.

The ```vulnerable-code``` directory contains example vulnerable code you can scan to test findings.  For now it is a vulnerable python app but I will add more languages as soon as possible.

