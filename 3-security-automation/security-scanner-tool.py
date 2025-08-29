#!/usr/bin/env python3
"""
Security Automation Tool - Amazon AppSec Interview Demo
======================================================

This tool demonstrates security automation capabilities for Amazon Application Security Engineer interviews.
It integrates multiple security scanning tools and provides AWS-native deployment options.

Features:
- Static code analysis (SAST)
- Dynamic security testing (DAST) 
- Dependency vulnerability scanning
- Infrastructure security scanning
- Integration with AWS Security Hub
- CI/CD pipeline integration

Usage: python security-scanner-tool.py --target <path/url> --scan-type <type>

DEFENSIVE PURPOSE ONLY - For security automation and development team assistance
"""

import argparse
import json
import os
import subprocess
import time
import boto3
import requests
from pathlib import Path
import concurrent.futures
from datetime import datetime, timezone
import yaml
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SecurityScanner:
    def __init__(self, aws_region='us-east-1'):
        self.aws_region = aws_region
        self.security_hub = None
        self.findings = []
        
        # Initialize AWS clients if credentials available
        try:
            self.security_hub = boto3.client('securityhub', region_name=aws_region)
            self.ssm = boto3.client('ssm', region_name=aws_region)
            logger.info("AWS integration enabled")
        except Exception as e:
            logger.warning(f"AWS integration disabled: {e}")
    
    def run_sast_scan(self, target_path, languages=['python', 'javascript', 'java']):
        """Run Static Application Security Testing"""
        logger.info(f"Running SAST scan on {target_path}")
        findings = []
        
        if 'python' in languages:
            findings.extend(self._run_bandit_scan(target_path))
        
        if 'javascript' in languages:
            findings.extend(self._run_semgrep_scan(target_path, 'javascript'))
            
        if 'java' in languages:
            findings.extend(self._run_semgrep_scan(target_path, 'java'))
        
        return findings
    
    def _run_bandit_scan(self, target_path):
        """Run Bandit security scanner for Python code"""
        try:
            cmd = [
                'bandit', '-r', target_path, '-f', 'json', 
                '--severity-level', 'medium'
            ]
            
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300
            )
            
            if result.returncode in [0, 1]:  # 0 = no issues, 1 = issues found
                bandit_output = json.loads(result.stdout)
                
                findings = []
                for issue in bandit_output.get('results', []):
                    finding = {
                        'tool': 'Bandit',
                        'type': 'SAST',
                        'severity': issue['issue_severity'].lower(),
                        'confidence': issue['issue_confidence'].lower(),
                        'title': issue['test_name'],
                        'description': issue['issue_text'],
                        'file': issue['filename'],
                        'line': issue['line_number'],
                        'code': issue['code'],
                        'cwe': self._map_bandit_to_cwe(issue['test_id']),
                        'remediation': self._get_remediation_advice(issue['test_id'])
                    }
                    findings.append(finding)
                
                logger.info(f"Bandit found {len(findings)} issues")
                return findings
                
        except subprocess.TimeoutExpired:
            logger.error("Bandit scan timed out")
        except FileNotFoundError:
            logger.warning("Bandit not installed - skipping Python SAST")
        except Exception as e:
            logger.error(f"Bandit scan failed: {e}")
        
        return []
    
    def _run_semgrep_scan(self, target_path, language):
        """Run Semgrep security scanner"""
        try:
            # Use language-specific rulesets
            ruleset_map = {
                'python': 'python.lang.security',
                'javascript': 'javascript.lang.security',
                'java': 'java.lang.security'
            }
            
            ruleset = ruleset_map.get(language, 'auto')
            
            cmd = [
                'semgrep', '--config', f'r/{ruleset}', 
                '--json', '--quiet', target_path
            ]
            
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600
            )
            
            if result.returncode == 0:
                semgrep_output = json.loads(result.stdout)
                
                findings = []
                for result_item in semgrep_output.get('results', []):
                    finding = {
                        'tool': 'Semgrep',
                        'type': 'SAST',
                        'severity': self._map_semgrep_severity(result_item.get('extra', {})),
                        'title': result_item['check_id'],
                        'description': result_item['extra'].get('message', 'Security issue detected'),
                        'file': result_item['path'],
                        'line': result_item['start']['line'],
                        'code': result_item['extra'].get('lines', ''),
                        'references': result_item['extra'].get('references', [])
                    }
                    findings.append(finding)
                
                logger.info(f"Semgrep found {len(findings)} {language} issues")
                return findings
                
        except subprocess.TimeoutExpired:
            logger.error(f"Semgrep {language} scan timed out")
        except FileNotFoundError:
            logger.warning("Semgrep not installed - skipping SAST")
        except Exception as e:
            logger.error(f"Semgrep {language} scan failed: {e}")
        
        return []
    
    def run_dependency_scan(self, target_path):
        """Run dependency vulnerability scanning"""
        logger.info("Running dependency vulnerability scan")
        findings = []
        
        # Check for different package managers
        if Path(target_path, 'requirements.txt').exists():
            findings.extend(self._run_safety_scan(target_path))
        
        if Path(target_path, 'package.json').exists():
            findings.extend(self._run_npm_audit(target_path))
        
        if Path(target_path, 'pom.xml').exists():
            findings.extend(self._run_owasp_dependency_check(target_path))
        
        return findings
    
    def _run_safety_scan(self, target_path):
        """Run Safety scanner for Python dependencies"""
        try:
            cmd = ['safety', 'check', '--json', '--full-report']
            
            result = subprocess.run(
                cmd, capture_output=True, text=True, 
                cwd=target_path, timeout=180
            )
            
            if result.returncode in [0, 64]:  # 0 = safe, 64 = vulnerabilities found
                try:
                    safety_output = json.loads(result.stdout)
                except json.JSONDecodeError:
                    logger.warning("Safety output not in JSON format")
                    return []
                
                findings = []
                for vuln in safety_output:
                    finding = {
                        'tool': 'Safety',
                        'type': 'Dependency',
                        'severity': 'high',  # Safety reports confirmed vulnerabilities
                        'title': f"Vulnerable dependency: {vuln['package_name']}",
                        'description': vuln['advisory'],
                        'package': vuln['package_name'],
                        'installed_version': vuln['installed_version'],
                        'affected_versions': vuln['affected_versions'],
                        'safe_versions': vuln.get('safe_versions', []),
                        'cve': vuln.get('cve', ''),
                        'remediation': f"Upgrade {vuln['package_name']} to a safe version"
                    }
                    findings.append(finding)
                
                logger.info(f"Safety found {len(findings)} vulnerable dependencies")
                return findings
                
        except subprocess.TimeoutExpired:
            logger.error("Safety scan timed out")
        except FileNotFoundError:
            logger.warning("Safety not installed - skipping Python dependency scan")
        except Exception as e:
            logger.error(f"Safety scan failed: {e}")
        
        return []
    
    def _run_npm_audit(self, target_path):
        """Run npm audit for JavaScript dependencies"""
        try:
            cmd = ['npm', 'audit', '--json']
            
            result = subprocess.run(
                cmd, capture_output=True, text=True, 
                cwd=target_path, timeout=180
            )
            
            # npm audit returns non-zero for vulnerabilities, which is expected
            try:
                audit_output = json.loads(result.stdout)
            except json.JSONDecodeError:
                logger.warning("npm audit output not in JSON format")
                return []
            
            findings = []
            vulnerabilities = audit_output.get('vulnerabilities', {})
            
            for package_name, vuln_info in vulnerabilities.items():
                severity = vuln_info.get('severity', 'unknown')
                
                finding = {
                    'tool': 'npm audit',
                    'type': 'Dependency',
                    'severity': severity,
                    'title': f"Vulnerable dependency: {package_name}",
                    'description': vuln_info.get('title', 'Vulnerability in dependency'),
                    'package': package_name,
                    'range': vuln_info.get('range', ''),
                    'via': vuln_info.get('via', []),
                    'remediation': f"Update {package_name} dependency"
                }
                findings.append(finding)
            
            logger.info(f"npm audit found {len(findings)} vulnerable dependencies")
            return findings
            
        except subprocess.TimeoutExpired:
            logger.error("npm audit timed out")
        except FileNotFoundError:
            logger.warning("npm not installed - skipping JavaScript dependency scan")
        except Exception as e:
            logger.error(f"npm audit failed: {e}")
        
        return []
    
    def run_dast_scan(self, target_url, scan_depth='quick'):
        """Run Dynamic Application Security Testing"""
        logger.info(f"Running DAST scan on {target_url}")
        
        # Basic security header checks
        findings = self._check_security_headers(target_url)
        
        # SSL/TLS configuration check
        findings.extend(self._check_ssl_config(target_url))
        
        # Basic vulnerability probes (educational purposes only)
        if scan_depth == 'full':
            findings.extend(self._run_basic_web_probes(target_url))
        
        return findings
    
    def _check_security_headers(self, url):
        """Check for security headers"""
        findings = []
        
        try:
            response = requests.get(url, timeout=10, verify=True)
            headers = response.headers
            
            # Check for missing security headers
            security_headers = {
                'Strict-Transport-Security': 'Missing HSTS header - enables HTTPS enforcement',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options - enables MIME sniffing attacks',
                'X-Frame-Options': 'Missing X-Frame-Options - enables clickjacking attacks',
                'X-XSS-Protection': 'Missing X-XSS-Protection - reduces XSS attack effectiveness',
                'Content-Security-Policy': 'Missing CSP - enables various injection attacks',
                'Referrer-Policy': 'Missing Referrer-Policy - may leak sensitive URLs'
            }
            
            for header, description in security_headers.items():
                if header not in headers:
                    finding = {
                        'tool': 'Security Headers Check',
                        'type': 'DAST',
                        'severity': 'medium',
                        'title': f'Missing Security Header: {header}',
                        'description': description,
                        'url': url,
                        'remediation': f'Add {header} header to web server configuration'
                    }
                    findings.append(finding)
            
            # Check for information disclosure headers
            disclosure_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version']
            for header in disclosure_headers:
                if header in headers:
                    finding = {
                        'tool': 'Security Headers Check',
                        'type': 'DAST',
                        'severity': 'low',
                        'title': f'Information Disclosure: {header}',
                        'description': f'Server exposes {header}: {headers[header]}',
                        'url': url,
                        'remediation': f'Remove or obfuscate {header} header'
                    }
                    findings.append(finding)
            
        except requests.RequestException as e:
            logger.error(f"Failed to check security headers: {e}")
        
        return findings
    
    def _check_ssl_config(self, url):
        """Check SSL/TLS configuration"""
        findings = []
        
        if not url.startswith('https://'):
            finding = {
                'tool': 'SSL Check',
                'type': 'DAST',
                'severity': 'high',
                'title': 'Insecure Protocol',
                'description': 'Application not using HTTPS encryption',
                'url': url,
                'remediation': 'Enable HTTPS with proper SSL/TLS configuration'
            }
            findings.append(finding)
        
        return findings
    
    def send_to_security_hub(self, findings, account_id=None):
        """Send findings to AWS Security Hub"""
        if not self.security_hub:
            logger.warning("AWS Security Hub not configured")
            return
        
        if not account_id:
            account_id = boto3.client('sts').get_caller_identity()['Account']
        
        hub_findings = []
        
        for finding in findings[:20]:  # Limit to 20 findings per batch
            hub_finding = {
                'SchemaVersion': '2018-10-08',
                'Id': f"security-scanner-{hash(str(finding))}",
                'ProductArn': f"arn:aws:securityhub:{self.aws_region}:{account_id}:product/{account_id}/default",
                'GeneratorId': 'security-automation-tool',
                'AwsAccountId': account_id,
                'CreatedAt': datetime.now(timezone.utc).isoformat(),
                'UpdatedAt': datetime.now(timezone.utc).isoformat(),
                'Severity': {
                    'Label': finding['severity'].upper()
                },
                'Title': finding['title'],
                'Description': finding['description'],
                'Types': [f"Software and Configuration Checks/{finding['type']}"]
            }
            
            # Add source location if available
            if 'file' in finding:
                hub_finding['SourceUrl'] = f"file://{finding['file']}"
            elif 'url' in finding:
                hub_finding['SourceUrl'] = finding['url']
            
            hub_findings.append(hub_finding)
        
        try:
            response = self.security_hub.batch_import_findings(Findings=hub_findings)
            logger.info(f"Sent {len(hub_findings)} findings to Security Hub")
            return response
        except Exception as e:
            logger.error(f"Failed to send findings to Security Hub: {e}")
    
    def generate_report(self, findings, output_format='json'):
        """Generate security scan report"""
        report_data = {
            'scan_timestamp': datetime.now().isoformat(),
            'total_findings': len(findings),
            'severity_breakdown': self._get_severity_breakdown(findings),
            'findings_by_tool': self._group_findings_by_tool(findings),
            'findings': findings
        }
        
        if output_format == 'json':
            return json.dumps(report_data, indent=2)
        elif output_format == 'yaml':
            return yaml.dump(report_data, default_flow_style=False)
        else:
            return self._generate_text_report(report_data)
    
    def _get_severity_breakdown(self, findings):
        """Get count of findings by severity"""
        breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in breakdown:
                breakdown[severity] += 1
        
        return breakdown
    
    def _group_findings_by_tool(self, findings):
        """Group findings by scanning tool"""
        grouped = {}
        
        for finding in findings:
            tool = finding.get('tool', 'Unknown')
            if tool not in grouped:
                grouped[tool] = []
            grouped[tool].append(finding)
        
        return {tool: len(findings) for tool, findings in grouped.items()}
    
    def _generate_text_report(self, report_data):
        """Generate human-readable text report"""
        report = []
        report.append("="*60)
        report.append("SECURITY SCAN REPORT")
        report.append("="*60)
        report.append(f"Scan Date: {report_data['scan_timestamp']}")
        report.append(f"Total Findings: {report_data['total_findings']}")
        report.append("")
        
        report.append("SEVERITY BREAKDOWN:")
        for severity, count in report_data['severity_breakdown'].items():
            report.append(f"  {severity.title()}: {count}")
        report.append("")
        
        report.append("FINDINGS BY TOOL:")
        for tool, count in report_data['findings_by_tool'].items():
            report.append(f"  {tool}: {count}")
        report.append("")
        
        # Show critical and high findings
        critical_high = [f for f in report_data['findings'] 
                        if f.get('severity', '').lower() in ['critical', 'high']]
        
        if critical_high:
            report.append("CRITICAL & HIGH SEVERITY FINDINGS:")
            report.append("-" * 40)
            
            for finding in critical_high[:10]:  # Limit to top 10
                report.append(f"• {finding['title']} ({finding['severity'].upper()})")
                report.append(f"  {finding['description']}")
                if 'file' in finding:
                    report.append(f"  File: {finding['file']}:{finding.get('line', '')}")
                report.append("")
        
        return "\n".join(report)
    
    # Helper methods for mapping and remediation
    def _map_bandit_to_cwe(self, test_id):
        """Map Bandit test IDs to CWE numbers"""
        mapping = {
            'B101': 'CWE-78',   # Shell injection
            'B102': 'CWE-78',   # Shell injection
            'B103': 'CWE-377',  # Insecure temporary file
            'B106': 'CWE-259',  # Hardcoded password
            'B107': 'CWE-259',  # Hardcoded password
            'B201': 'CWE-22',   # Path traversal
            'B301': 'CWE-78',   # Subprocess injection
            'B501': 'CWE-295',  # SSL verification disabled
            'B506': 'CWE-377'   # Unsafe yaml load
        }
        return mapping.get(test_id, 'CWE-699')
    
    def _map_semgrep_severity(self, extra_info):
        """Map Semgrep severity information"""
        severity_map = {
            'ERROR': 'high',
            'WARNING': 'medium',
            'INFO': 'low'
        }
        
        severity = extra_info.get('severity', 'INFO')
        return severity_map.get(severity.upper(), 'medium')
    
    def _get_remediation_advice(self, test_id):
        """Get remediation advice for Bandit findings"""
        remediation = {
            'B101': 'Use subprocess.run() with shell=False and proper input validation',
            'B102': 'Use subprocess.run() with shell=False and proper input validation', 
            'B106': 'Store secrets in environment variables or secure key management',
            'B107': 'Store secrets in environment variables or secure key management',
            'B501': 'Enable SSL certificate verification in production',
            'B506': 'Use yaml.safe_load() instead of yaml.load()'
        }
        return remediation.get(test_id, 'Review code for security best practices')


def create_ci_cd_integration():
    """Generate CI/CD pipeline integration examples"""
    
    # GitHub Actions workflow
    github_workflow = """
name: Security Scan

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: 3.9
    
    - name: Install security tools
      run: |
        pip install bandit safety semgrep
        npm install -g @aws-cdk/cli
    
    - name: Run Security Scanner
      env:
        AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
        AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
      run: |
        python security-scanner-tool.py --target . --scan-type all --output github
    
    - name: Upload Security Report
      uses: actions/upload-artifact@v2
      with:
        name: security-report
        path: security-report.json
"""

    # Jenkins pipeline
    jenkins_pipeline = """
pipeline {
    agent any
    
    environment {
        AWS_REGION = 'us-east-1'
    }
    
    stages {
        stage('Security Scan') {
            steps {
                script {
                    // Install security tools
                    sh 'pip install bandit safety semgrep'
                    
                    // Run comprehensive security scan
                    sh 'python security-scanner-tool.py --target . --scan-type all --output jenkins'
                    
                    // Archive results
                    archiveArtifacts artifacts: 'security-report.*', fingerprint: true
                    
                    // Fail build if critical vulnerabilities found
                    sh '''
                        CRITICAL_COUNT=$(jq '.severity_breakdown.critical' security-report.json)
                        if [ "$CRITICAL_COUNT" -gt 0 ]; then
                            echo "Critical vulnerabilities found: $CRITICAL_COUNT"
                            exit 1
                        fi
                    '''
                }
            }
        }
    }
    
    post {
        always {
            publishHTML([
                allowMissing: false,
                alwaysLinkToLastBuild: true,
                keepAll: true,
                reportDir: '.',
                reportFiles: 'security-report.html',
                reportName: 'Security Scan Report'
            ])
        }
    }
}
"""
    
    return github_workflow, jenkins_pipeline


def main():
    parser = argparse.ArgumentParser(description='Security Automation Tool')
    parser.add_argument('--target', required=True, 
                       help='Target directory or URL to scan')
    parser.add_argument('--scan-type', choices=['sast', 'dast', 'deps', 'all'], 
                       default='all', help='Type of security scan to run')
    parser.add_argument('--output', choices=['json', 'yaml', 'text'], 
                       default='text', help='Output format')
    parser.add_argument('--send-to-hub', action='store_true',
                       help='Send findings to AWS Security Hub')
    parser.add_argument('--aws-region', default='us-east-1',
                       help='AWS region for Security Hub')
    
    args = parser.parse_args()
    
    scanner = SecurityScanner(aws_region=args.aws_region)
    all_findings = []
    
    if args.scan_type in ['sast', 'all']:
        if os.path.exists(args.target):
            sast_findings = scanner.run_sast_scan(args.target)
            all_findings.extend(sast_findings)
        else:
            logger.warning("Target path doesn't exist - skipping SAST scan")
    
    if args.scan_type in ['deps', 'all']:
        if os.path.exists(args.target):
            dep_findings = scanner.run_dependency_scan(args.target)
            all_findings.extend(dep_findings)
        else:
            logger.warning("Target path doesn't exist - skipping dependency scan")
    
    if args.scan_type in ['dast', 'all']:
        if args.target.startswith(('http://', 'https://')):
            dast_findings = scanner.run_dast_scan(args.target)
            all_findings.extend(dast_findings)
        else:
            logger.warning("Target is not a URL - skipping DAST scan")
    
    # Generate and display report
    report = scanner.generate_report(all_findings, args.output)
    print(report)
    
    # Save report to file
    filename = f"security-report.{args.output}"
    with open(filename, 'w') as f:
        f.write(report)
    
    logger.info(f"Report saved to {filename}")
    
    # Send to Security Hub if requested
    if args.send_to_hub:
        scanner.send_to_security_hub(all_findings)
    
    # Exit with error code if critical findings
    critical_count = sum(1 for f in all_findings if f.get('severity') == 'critical')
    if critical_count > 0:
        logger.error(f"Found {critical_count} critical security issues")
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main())