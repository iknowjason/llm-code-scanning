import os
import sys
import argparse
import json
from pathlib import Path
import openai
from typing import List, Dict, Any
import logging
import time

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('llm-security-scanner')

class CodeSecurityScanner:
    """
    A security scanner that uses LLMs to detect vulnerabilities in code.
    """
    
    def __init__(self, api_key: str, model: str = "gpt-4", provider: str = "openai"):
        """
        Initialize the scanner with the API key and model.
        
        Args:
            api_key: API key for the LLM provider
            model: Model to use (default: gpt-4)
            provider: LLM provider (openai or anthropic)
        """
        self.provider = provider
        self.model = model
        
        if provider == "openai":
            openai.api_key = api_key
            self.api_key = api_key
        elif provider == "anthropic":
            # Anthropic's Claude API
            import anthropic
            self.client = anthropic.Anthropic(api_key=api_key)
        else:
            raise ValueError(f"Unsupported provider: {provider}")
        
        logger.info(f"Initialized {provider} client with model {model}")
    
    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        Scan a single file for security vulnerabilities.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            Dictionary containing the scan results
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
            
            file_extension = Path(file_path).suffix.lower()
            language = self._detect_language(file_extension)
            
            if not language:
                logger.warning(f"Unsupported file type: {file_extension}. Skipping {file_path}")
                return {"file": file_path, "status": "skipped", "reason": "unsupported_file_type"}
                
            # Analyze the code using the LLM
            vulnerabilities = self._analyze_code(code, language)
            
            return {
                "file": file_path,
                "status": "completed",
                "language": language,
                "vulnerabilities": vulnerabilities
            }
            
        except Exception as e:
            logger.error(f"Error scanning file {file_path}: {str(e)}")
            return {"file": file_path, "status": "error", "error": str(e)}
    
    def scan_directory(self, directory_path: str, recursive: bool = True, exclude_dirs: List[str] = None) -> List[Dict[str, Any]]:
        """
        Scan all files in a directory for security vulnerabilities.
        
        Args:
            directory_path: Path to the directory to scan
            recursive: Whether to scan subdirectories
            exclude_dirs: List of directory names to exclude
            
        Returns:
            List of dictionaries containing scan results for each file
        """
        if exclude_dirs is None:
            exclude_dirs = [".git", "node_modules", "venv", "__pycache__", ".env"]
            
        results = []
        
        walk_dir = Path(directory_path)
        logger.info(f"Scanning directory: {walk_dir}")
        
        for path in self._get_files_to_scan(walk_dir, recursive, exclude_dirs):
            logger.info(f"Scanning file: {path}")
            result = self.scan_file(str(path))
            results.append(result)
            
        return results
    
    def _get_files_to_scan(self, directory: Path, recursive: bool, exclude_dirs: List[str]) -> List[Path]:
        """
        Get a list of files to scan in the directory.
        
        Args:
            directory: Directory to scan
            recursive: Whether to scan subdirectories
            exclude_dirs: List of directory names to exclude
            
        Returns:
            List of file paths to scan
        """
        files_to_scan = []
        
        if recursive:
            for path in directory.rglob('*'):
                if self._should_scan_file(path, exclude_dirs):
                    files_to_scan.append(path)
        else:
            for path in directory.glob('*'):
                if self._should_scan_file(path, exclude_dirs):
                    files_to_scan.append(path)
                    
        return files_to_scan
    
    def _should_scan_file(self, path: Path, exclude_dirs: List[str]) -> bool:
        """
        Determine whether a file should be scanned.
        
        Args:
            path: Path to check
            exclude_dirs: List of directory names to exclude
            
        Returns:
            True if the file should be scanned, False otherwise
        """
        # Skip directories
        if path.is_dir():
            return False
            
        # Skip files in excluded directories
        for parent in path.parents:
            if parent.name in exclude_dirs:
                return False
                
        # Only scan files with supported extensions
        extension = path.suffix.lower()
        return extension in ['.py', '.js', '.ts', '.java', '.c', '.cpp', '.go', '.php', '.rb']
    
    def _detect_language(self, file_extension: str) -> str:
        """
        Detect the programming language based on file extension.
        
        Args:
            file_extension: File extension
            
        Returns:
            Programming language name or None if unsupported
        """
        extension_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.java': 'java',
            '.c': 'c',
            '.cpp': 'c++',
            '.go': 'go',
            '.php': 'php',
            '.rb': 'ruby'
        }
        
        return extension_map.get(file_extension)
    
    def _analyze_code(self, code: str, language: str) -> List[Dict[str, Any]]:
        """
        Analyze code for security vulnerabilities using an LLM.
        
        Args:
            code: Source code to analyze
            language: Programming language
            
        Returns:
            List of identified vulnerabilities with details
        """
        # Build the prompt for the LLM
        prompt = self._build_security_prompt(code, language)
        
        if self.provider == "openai":
            return self._analyze_with_openai(prompt)
        elif self.provider == "anthropic":
            return self._analyze_with_anthropic(prompt)
        else:
            raise ValueError(f"Unsupported provider: {self.provider}")
    
    def _build_security_prompt(self, code: str, language: str) -> str:
        """
        Build a prompt for the LLM to analyze code for security vulnerabilities.
        
        Args:
            code: Source code to analyze
            language: Programming language
            
        Returns:
            Prompt for the LLM
        """
        return f"""
        You are a cybersecurity expert specializing in secure coding practices and vulnerability detection.
        
        Analyze the following {language} code for security vulnerabilities, focusing on:
        
        1. Common vulnerabilities specific to {language}
        2. Injection vulnerabilities (SQL, command, etc.)
        3. Authentication and authorization issues
        4. Data validation and sanitization problems
        5. Cryptographic flaws
        6. Hardcoded credentials or secrets
        7. Insecure configurations
        8. Race conditions or concurrency issues
        9. Error handling that leaks sensitive information
        10. Any other security concerns
        
        For each vulnerability found, provide:
        1. A brief description of the vulnerability
        2. The severity level (Critical, High, Medium, Low, or Info)
        3. The specific line number(s) where the issue occurs
        4. The potential impact of exploiting the vulnerability
        5. A recommended fix with code example
        
        Format your response as a JSON array of objects, each representing a vulnerability, with the following structure:
        
        [
            {{
                "vulnerability_type": "Type of vulnerability",
                "description": "Brief description",
                "severity": "Severity level",
                "line_numbers": [line numbers],
                "impact": "Potential impact",
                "recommendation": "Recommended fix",
                "fix_example": "Code example"
            }},
            // additional vulnerabilities...
        ]
        
        If no vulnerabilities are found, return an empty array: []
        
        Here is the code to analyze:
        
        ```{language}
        {code}
        ```
        
        Provide only the JSON output without any additional text.
        """
    
    def _analyze_with_openai(self, prompt: str) -> List[Dict[str, Any]]:
        """
        Analyze code using OpenAI's API.
        
        Args:
            prompt: Prompt for the LLM
            
        Returns:
            List of identified vulnerabilities with details
        """
        try:
            client = openai.OpenAI(api_key=openai.api_key)
            
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert that analyzes code for security vulnerabilities."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.0  # Use deterministic output
            )
            
            result = response.choices[0].message.content.strip()
            
            try:
                vulnerabilities = json.loads(result)
                return vulnerabilities
            except json.JSONDecodeError:
                logger.error(f"Failed to parse LLM response as JSON: {result}")
                return []
                
        except Exception as e:
            logger.error(f"Error calling OpenAI API: {str(e)}")
            # Wait a bit in case we hit rate limits
            time.sleep(2)
            return []
    
    def _analyze_with_anthropic(self, prompt: str) -> List[Dict[str, Any]]:
        """
        Analyze code using Anthropic's Claude API.
        
        Args:
            prompt: Prompt for the LLM
            
        Returns:
            List of identified vulnerabilities with details
        """
        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=4000,
                messages=[
                    {"role": "user", "content": prompt}
                ],
                temperature=0.0  # Use deterministic output
            )
            
            result = response.content[0].text.strip()
            
            try:
                # Parse the JSON response
                vulnerabilities = json.loads(result)
                return vulnerabilities
            except json.JSONDecodeError:
                logger.error(f"Failed to parse LLM response as JSON: {result}")
                return []
                
        except Exception as e:
            logger.error(f"Error calling Anthropic API: {str(e)}")
            # Wait a bit in case we hit rate limits
            time.sleep(2)
            return []

def generate_report(results: List[Dict[str, Any]], output_format: str = 'json', output_file: str = None) -> None:
    """
    Generate a report from scan results.
    
    Args:
        results: Scan results
        output_format: Output format (json or markdown)
        output_file: Output file path
    """
    vulnerable_files = 0
    total_vulnerabilities = 0
    
    for result in results:
        if result.get('status') == 'completed' and result.get('vulnerabilities'):
            vulnerable_files += 1
            total_vulnerabilities += len(result.get('vulnerabilities', []))
    
    summary = {
        "total_files_scanned": len(results),
        "vulnerable_files": vulnerable_files,
        "total_vulnerabilities": total_vulnerabilities
    }
    
    if output_format == 'json':
        report = {
            "summary": summary,
            "results": results
        }
        
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2)
        else:
            print(json.dumps(report, indent=2))
            
    elif output_format == 'markdown':
        markdown = "# Security Scan Report\n\n"
        markdown += f"## Summary\n\n"
        markdown += f"- Total Files Scanned: {summary['total_files_scanned']}\n"
        markdown += f"- Files with Vulnerabilities: {summary['vulnerable_files']}\n"
        markdown += f"- Total Vulnerabilities Found: {summary['total_vulnerabilities']}\n\n"
        
        if total_vulnerabilities > 0:
            markdown += "## Vulnerabilities\n\n"
            
            for result in results:
                if result.get('status') == 'completed' and result.get('vulnerabilities'):
                    markdown += f"### {result['file']}\n\n"
                    
                    for vuln in result.get('vulnerabilities', []):
                        markdown += f"#### {vuln.get('vulnerability_type', 'Unknown Vulnerability')}\n\n"
                        markdown += f"- **Severity**: {vuln.get('severity', 'Unknown')}\n"
                        markdown += f"- **Line Numbers**: {', '.join(map(str, vuln.get('line_numbers', [])))}\n"
                        markdown += f"- **Description**: {vuln.get('description', 'No description provided')}\n"
                        markdown += f"- **Impact**: {vuln.get('impact', 'Unknown impact')}\n"
                        markdown += f"- **Recommendation**: {vuln.get('recommendation', 'No recommendation provided')}\n"
                        
                        if vuln.get('fix_example'):
                            markdown += "\n**Fix Example**:\n\n```\n"
                            markdown += f"{vuln.get('fix_example')}\n"
                            markdown += "```\n\n"
                            
        else:
            markdown += "## No Vulnerabilities Found\n\n"
            markdown += "Congratulations! No security vulnerabilities were detected in the scanned files.\n"
            
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(markdown)
        else:
            print(markdown)
            
    else:
        raise ValueError(f"Unsupported output format: {output_format}")

def main():
    parser = argparse.ArgumentParser(description='LLM-based Code Security Scanner')
    
    # API configuration
    api_group = parser.add_argument_group('API Configuration')
    api_group.add_argument('--provider', choices=['openai', 'anthropic'], default='openai',
                          help='LLM provider (default: openai)')
    api_group.add_argument('--api-key', help='API key for the LLM provider (can also be set with OPENAI_API_KEY or ANTHROPIC_API_KEY env var)')
    api_group.add_argument('--model', help='Model to use (default depends on provider)')
    
    # Scanning options
    scan_group = parser.add_argument_group('Scanning Options')
    scan_group.add_argument('--file', help='Scan a single file')
    scan_group.add_argument('--directory', help='Scan a directory')
    scan_group.add_argument('--recursive', action='store_true', default=True,
                           help='Recursively scan directories (default: True)')
    scan_group.add_argument('--exclude-dirs', nargs='+', default=[".git", "node_modules", "venv", "__pycache__", ".env"],
                           help='Directory names to exclude from scanning')
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--output-format', choices=['json', 'markdown'], default='json',
                             help='Output format (default: json)')
    output_group.add_argument('--output-file', help='Output file path')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.file and not args.directory:
        parser.error('Either --file or --directory must be specified')
        
    if args.file and args.directory:
        parser.error('Only one of --file or --directory can be specified')
        
    # Get API key from args or environment variables
    api_key = args.api_key
    if not api_key:
        if args.provider == 'openai':
            api_key = os.getenv('OPENAI_API_KEY')
        elif args.provider == 'anthropic':
            api_key = os.getenv('ANTHROPIC_API_KEY')
            
    if not api_key:
        parser.error(f'{args.provider.upper()}_API_KEY environment variable or --api-key must be set')
        
    # Set default model based on provider
    model = args.model
    if not model:
        if args.provider == 'openai':
            model = 'gpt-4'
        elif args.provider == 'anthropic':
            model = 'claude-3-opus-20240229'
    
    # Initialize scanner
    scanner = CodeSecurityScanner(api_key=api_key, model=model, provider=args.provider)
    
    # Perform scan
    if args.file:
        results = [scanner.scan_file(args.file)]
    else:
        results = scanner.scan_directory(
            args.directory,
            recursive=args.recursive,
            exclude_dirs=args.exclude_dirs
        )
    
    # Generate report
    generate_report(results, args.output_format, args.output_file)
    
if __name__ == '__main__':
    main()
