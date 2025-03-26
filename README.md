# LLM-Based Code Security Scanner

This project implements a security scanning solution that leverages Large Language Models (LLMs) like GPT-4 or Claude to detect vulnerabilities in your codebase. It can be run locally as a CLI tool or integrated into your CI/CD pipeline using GitHub Actions.

## Features

- Uses LLMs to detect security vulnerabilities in code
- Supports multiple programming languages (Python, JavaScript, TypeScript, Java, C/C++, Go, PHP, Ruby)
- Provides detailed vulnerability information including:
  - Vulnerability type and description
  - Severity rating
  - Line numbers where the issue occurs
  - Potential impact of the vulnerability
  - Recommended fixes with code examples
- Can be run locally or in CI/CD pipelines
- Creates GitHub issues for detected vulnerabilities
- Supports both OpenAI and Anthropic LLMs

## Prerequisites

- Python 3.8 or later
- An API key from OpenAI or Anthropic
- GitHub repository for CI/CD integration

## Installation

1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/llm-code-security-scanner.git
   cd llm-code-security-scanner
   ```

2. Install required packages:
   ```bash
   pip install openai anthropic
   ```

3. Set up your API key:
   - For OpenAI:
     ```bash
     export OPENAI_API_KEY="your-api-key-here"
     ```
   - For Anthropic:
     ```bash
     export ANTHROPIC_API_KEY="your-api-key-here"
     ```

## Local Usage

The script is located in the ```script``` directory.  The scanner can be used to check a single file or an entire directory:

```bash
# Scan a single file
python llm_security_scanner.py --file path/to/your/file.py

# Scan a directory
python llm_security_scanner.py --directory path/to/your/project

# Specify output format
python llm_security_scanner.py --directory path/to/your/project --output-format markdown --output-file scan-results.md

# Use Anthropic's Claude instead of OpenAI
python llm_security_scanner.py --file path/to/your/file.py --provider anthropic
```

## GitHub Actions Integration

To integrate the security scanner into your GitHub workflow:

1. Create the following directories in your repository if they don't exist:
   ```bash
   mkdir -p .github/workflows
   mkdir -p .github/scripts
   ```

2. Copy the `llm_security_scanner.py` file to `.github/scripts/`:
   ```bash
   cp llm_security_scanner.py .github/scripts/
   ```

3. Copy the workflow file to `.github/workflows/`:
   ```bash
   cp llm-security-scan.yml .github/workflows/
   ```

4. Add your API key as a GitHub secret:
   - Go to your repository on GitHub
   - Click on "Settings" > "Secrets and variables" > "Actions"
   - Click "New repository secret"
   - Name: `OPENAI_API_KEY` or `ANTHROPIC_API_KEY`
   - Value: Your API key

5. Commit and push the changes:
   ```bash
   git add .github
   git commit -m "Add LLM-based security scanning"
   git push
   ```

The workflow will now run on:
- Every push to the `main` branch
- Every pull request to the `main` branch
- Weekly on Monday at 8:00 AM UTC

## How It Works

The security scanner uses the following approach:

1. **Code Analysis**: The scanner extracts the code from files and sends it to an LLM with a specially crafted prompt that instructs the model to analyze the code for security vulnerabilities.

2. **Vulnerability Detection**: The LLM processes the code and identifies potential security issues, providing detailed information about each vulnerability.

3. **Report Generation**: The scanner generates a report in either JSON or Markdown format, detailing the findings.

4. **Issue Creation**: When run in GitHub Actions, the scanner creates GitHub issues for medium to critical severity vulnerabilities, making them easy to track and fix.

## Customization

You can customize the behavior of the scanner by modifying:

- The security prompt in the `_build_security_prompt` method
- The vulnerability types to check for
- The severity thresholds for issue creation
- The exclusion list for directories to skip

## Limitations

- The accuracy of vulnerability detection depends on the capabilities of the LLM being used
- Large files may exceed token limits of the LLM
- API costs can add up for large codebases
- The scanner may produce false positives or miss certain vulnerabilities

## License

[MIT License](LICENSE)

## Acknowledgements

This project was inspired by research showing that LLMs can effectively identify code vulnerabilities and provide useful remediation guidance.

- Steve Sims for research idea
- Melanie Hart Buehler for her research:

https://towardsdatascience.com/detecting-insecure-code-with-llms-8b8ad923dd98/

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

