#!/usr/bin/env python3
"""
Vibe-Code Detector Core Analysis Engine
Analyzes code repositories for vibe-coding patterns and technical debt
"""

import os
import re
import ast
import json
import hashlib
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import subprocess
import tempfile
import shutil

@dataclass
class Finding:
    """Represents a single finding in the analysis"""
    file_path: str
    line_number: int
    description: str
    severity: str  # Critical, High, Medium, Low
    category: str
    fix_suggestion: str
    confidence: float  # 0.0 to 1.0
    code_snippet: str = ""

@dataclass
class AnalysisReport:
    """Complete analysis report for a repository"""
    repository: str
    timestamp: str
    vibe_coding_score: int  # 0-100
    technical_debt_hours: int
    critical_vulnerabilities: int
    high_issues: int
    medium_issues: int
    low_issues: int
    findings: List[Finding]
    summary: str
    recommendations: List[str]

class VibeCodeAnalyzer:
    """Main analyzer class for detecting vibe-coding patterns"""
    
    def __init__(self):
        self.findings: List[Finding] = []
        self.file_extensions = {
            '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.cpp', '.c', 
            '.cs', '.php', '.rb', '.go', '.rs', '.swift', '.kt'
        }
        
    def analyze_repository(self, repo_path: str) -> AnalysisReport:
        """Analyze a complete repository"""
        self.findings = []
        
        # Walk through all files
        for root, dirs, files in os.walk(repo_path):
            # Skip common directories to ignore
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'target', 'build', 'dist'}]
            
            for file in files:
                file_path = os.path.join(root, file)
                if Path(file_path).suffix in self.file_extensions:
                    self._analyze_file(file_path, repo_path)
        
        # Generate report
        return self._generate_report(repo_path)
    
    def _analyze_file(self, file_path: str, repo_path: str):
        """Analyze a single file for issues"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            relative_path = os.path.relpath(file_path, repo_path)
            extension = Path(file_path).suffix
            
            # Language-specific analysis
            if extension == '.py':
                self._analyze_python_file(content, relative_path)
            elif extension in {'.js', '.ts', '.jsx', '.tsx'}:
                self._analyze_javascript_file(content, relative_path)
            elif extension in {'.java', '.cpp', '.c', '.cs'}:
                self._analyze_compiled_language_file(content, relative_path)
            
            # General patterns
            self._analyze_general_patterns(content, relative_path)
            
        except Exception as e:
            # Log error but continue analysis
            print(f"Error analyzing {file_path}: {e}")
    
    def _analyze_python_file(self, content: str, file_path: str):
        """Analyze Python-specific patterns"""
        try:
            tree = ast.parse(content)
            
            # Check for hardcoded credentials
            self._check_hardcoded_credentials(content, file_path)
            
            # Check for print statements in production code
            self._check_print_statements(content, file_path)
            
            # Check for broad exception handling
            self._check_broad_exceptions(content, file_path)
            
            # Check for unused imports
            self._check_unused_imports(tree, file_path)
            
        except SyntaxError:
            # File has syntax errors
            self.findings.append(Finding(
                file_path=file_path,
                line_number=1,
                description="Syntax error in Python file",
                severity="High",
                category="Code Quality",
                fix_suggestion="Fix syntax errors before analysis",
                confidence=1.0
            ))
    
    def _analyze_javascript_file(self, content: str, file_path: str):
        """Analyze JavaScript/TypeScript patterns"""
        # Check for console.log statements
        self._check_console_logs(content, file_path)
        
        # Check for hardcoded credentials
        self._check_hardcoded_credentials(content, file_path)
        
        # Check for eval usage
        self._check_eval_usage(content, file_path)
    
    def _analyze_compiled_language_file(self, content: str, file_path: str):
        """Analyze compiled language patterns"""
        # Check for hardcoded credentials
        self._check_hardcoded_credentials(content, file_path)
        
        # Check for magic numbers
        self._check_magic_numbers(content, file_path)
    
    def _analyze_general_patterns(self, content: str, file_path: str):
        """Analyze general patterns across all languages"""
        lines = content.split('\n')
        
        for i, line in enumerate(lines, 1):
            # Check for TODO comments
            if re.search(r'\bTODO\b', line, re.IGNORECASE):
                self.findings.append(Finding(
                    file_path=file_path,
                    line_number=i,
                    description="TODO comment found",
                    severity="Low",
                    category="Code Quality",
                    fix_suggestion="Address TODO items or remove if obsolete",
                    confidence=0.8,
                    code_snippet=line.strip()
                ))
            
            # Check for FIXME comments
            if re.search(r'\bFIXME\b', line, re.IGNORECASE):
                self.findings.append(Finding(
                    file_path=file_path,
                    line_number=i,
                    description="FIXME comment found",
                    severity="Medium",
                    category="Code Quality",
                    fix_suggestion="Address FIXME items or remove if obsolete",
                    confidence=0.9,
                    code_snippet=line.strip()
                ))
    
    def _check_hardcoded_credentials(self, content: str, file_path: str):
        """Check for hardcoded credentials"""
        patterns = [
            (r'password\s*=\s*["\'][^"\']+["\']', "Hardcoded password"),
            (r'api_key\s*=\s*["\'][^"\']+["\']', "Hardcoded API key"),
            (r'secret\s*=\s*["\'][^"\']+["\']', "Hardcoded secret"),
            (r'token\s*=\s*["\'][^"\']+["\']', "Hardcoded token"),
        ]
        
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            for pattern, description in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    self.findings.append(Finding(
                        file_path=file_path,
                        line_number=i,
                        description=description,
                        severity="Critical",
                        category="Security",
                        fix_suggestion="Move credentials to environment variables or secure configuration",
                        confidence=0.9,
                        code_snippet=line.strip()
                    ))
    
    def _check_print_statements(self, content: str, file_path: str):
        """Check for print statements in Python"""
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'\bprint\s*\(', line):
                self.findings.append(Finding(
                    file_path=file_path,
                    line_number=i,
                    description="Print statement found",
                    severity="Low",
                    category="Code Quality",
                    fix_suggestion="Replace with proper logging",
                    confidence=0.8,
                    code_snippet=line.strip()
                ))
    
    def _check_console_logs(self, content: str, file_path: str):
        """Check for console.log statements in JavaScript"""
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'console\.log\s*\(', line):
                self.findings.append(Finding(
                    file_path=file_path,
                    line_number=i,
                    description="Console.log statement found",
                    severity="Low",
                    category="Code Quality",
                    fix_suggestion="Replace with proper logging or remove for production",
                    confidence=0.8,
                    code_snippet=line.strip()
                ))
    
    def _check_eval_usage(self, content: str, file_path: str):
        """Check for eval usage in JavaScript"""
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'\beval\s*\(', line):
                self.findings.append(Finding(
                    file_path=file_path,
                    line_number=i,
                    description="Eval usage found",
                    severity="Critical",
                    category="Security",
                    fix_suggestion="Avoid eval() - use safer alternatives",
                    confidence=0.9,
                    code_snippet=line.strip()
                ))
    
    def _check_broad_exceptions(self, content: str, file_path: str):
        """Check for broad exception handling in Python"""
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            if re.search(r'except\s*:', line):
                self.findings.append(Finding(
                    file_path=file_path,
                    line_number=i,
                    description="Broad exception handling",
                    severity="Medium",
                    category="Code Quality",
                    fix_suggestion="Catch specific exceptions instead of bare except",
                    confidence=0.8,
                    code_snippet=line.strip()
                ))
    
    def _check_unused_imports(self, tree: ast.AST, file_path: str):
        """Check for unused imports in Python"""
        # This is a simplified check - in practice you'd need more sophisticated analysis
        pass
    
    def _check_magic_numbers(self, content: str, file_path: str):
        """Check for magic numbers in code"""
        lines = content.split('\n')
        for i, line in enumerate(lines, 1):
            # Look for numbers that might be magic numbers
            numbers = re.findall(r'\b\d{2,}\b', line)
            for number in numbers:
                if int(number) > 100:  # Arbitrary threshold
                    self.findings.append(Finding(
                        file_path=file_path,
                        line_number=i,
                        description=f"Potential magic number: {number}",
                        severity="Low",
                        category="Code Quality",
                        fix_suggestion="Define as named constant",
                        confidence=0.6,
                        code_snippet=line.strip()
                    ))
    
    def _generate_report(self, repo_path: str) -> AnalysisReport:
        """Generate the final analysis report"""
        # Count findings by severity
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for finding in self.findings:
            severity_counts[finding.severity] += 1
        
        # Calculate vibe-coding score (0-100)
        total_issues = len(self.findings)
        critical_weight = 10
        high_weight = 5
        medium_weight = 2
        low_weight = 1
        
        weighted_score = (
            severity_counts['Critical'] * critical_weight +
            severity_counts['High'] * high_weight +
            severity_counts['Medium'] * medium_weight +
            severity_counts['Low'] * low_weight
        )
        
        # Convert to 0-100 scale (inverse relationship)
        max_possible_score = 100
        vibe_coding_score = max(0, max_possible_score - min(weighted_score * 2, max_possible_score))
        
        # Estimate technical debt hours
        technical_debt_hours = (
            severity_counts['Critical'] * 4 +
            severity_counts['High'] * 2 +
            severity_counts['Medium'] * 1 +
            severity_counts['Low'] * 0.5
        )
        
        # Generate recommendations
        recommendations = []
        if severity_counts['Critical'] > 0:
            recommendations.append("Address critical security issues immediately")
        if severity_counts['High'] > 5:
            recommendations.append("Review and fix high-priority issues")
        if technical_debt_hours > 20:
            recommendations.append("Consider technical debt reduction sprint")
        if vibe_coding_score < 50:
            recommendations.append("Implement code quality improvements")
        
        return AnalysisReport(
            repository=os.path.basename(repo_path),
            timestamp=datetime.now().isoformat(),
            vibe_coding_score=int(vibe_coding_score),
            technical_debt_hours=int(technical_debt_hours),
            critical_vulnerabilities=severity_counts['Critical'],
            high_issues=severity_counts['High'],
            medium_issues=severity_counts['Medium'],
            low_issues=severity_counts['Low'],
            findings=self.findings,
            summary=f"Found {total_issues} issues across {len(set(f.file_path for f in self.findings))} files",
            recommendations=recommendations
        )

class ReportFormatter:
    """Formats analysis reports into different output formats"""
    
    @staticmethod
    def to_json(report: AnalysisReport) -> str:
        """Convert report to JSON format"""
        # Convert findings to dict format
        findings_dict = []
        for finding in report.findings:
            findings_dict.append(asdict(finding))
        
        report_dict = asdict(report)
        report_dict['findings'] = findings_dict
        
        return json.dumps(report_dict, indent=2)
    
    @staticmethod
    def to_markdown(report: AnalysisReport) -> str:
        """Convert report to Markdown format"""
        lines = []
        lines.append("# Vibe-Code Analysis Report\n")
        lines.append(f"**Repository**: {report.repository}")
        lines.append(f"**Generated**: {report.timestamp}\n")
        
        lines.append("## Executive Summary\n")
        lines.append(f"- **Vibe-Coding Score**: {report.vibe_coding_score}/100")
        lines.append(f"- **Technical Debt**: {report.technical_debt_hours} hours")
        lines.append(f"- **Total Issues**: {len(report.findings)}")
        lines.append(f"- **Critical**: {report.critical_vulnerabilities}")
        lines.append(f"- **High**: {report.high_issues}")
        lines.append(f"- **Medium**: {report.medium_issues}")
        lines.append(f"- **Low**: {report.low_issues}\n")
        
        if report.recommendations:
            lines.append("## Recommendations\n")
            for rec in report.recommendations:
                lines.append(f"- {rec}")
            lines.append("")
        
        # Group findings by severity
        findings_by_severity = {'Critical': [], 'High': [], 'Medium': [], 'Low': []}
        for finding in report.findings:
            findings_by_severity[finding.severity].append(finding)
        
        for severity, findings in findings_by_severity.items():
            if findings:
                lines.append(f"## {severity} Issues ({len(findings)})\n")
                for finding in findings:
                    lines.append(f"### {finding.description}")
                    lines.append(f"**File**: `{finding.file_path}:{finding.line_number}`")
                    lines.append(f"**Category**: {finding.category}")
                    lines.append(f"**Fix**: {finding.fix_suggestion}")
                    lines.append(f"**Confidence**: {finding.confidence*100:.0f}%")
                    if finding.code_snippet:
                        lines.append(f"**Code**: `{finding.code_snippet}`")
                    lines.append("")
        
        return '\n'.join(lines)
    
    @staticmethod
    def to_html(report: AnalysisReport) -> str:
        """Convert report to HTML format"""
        # This would generate a complete HTML report
        # For brevity, returning a simple HTML structure
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vibe-Code Analysis - {report.repository}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 40px; }}
                .score {{ font-size: 24px; font-weight: bold; }}
                .critical {{ color: #d32f2f; }}
                .high {{ color: #f57c00; }}
                .medium {{ color: #fbc02d; }}
                .low {{ color: #388e3c; }}
            </style>
        </head>
        <body>
            <h1>Vibe-Code Analysis Report</h1>
            <p><strong>Repository:</strong> {report.repository}</p>
            <p><strong>Generated:</strong> {report.timestamp}</p>
            
            <h2>Executive Summary</h2>
            <p class="score">Vibe-Coding Score: {report.vibe_coding_score}/100</p>
            <p>Technical Debt: {report.technical_debt_hours} hours</p>
            <p>Total Issues: {len(report.findings)}</p>
            
            <h2>Issues by Severity</h2>
            <p class="critical">Critical: {report.critical_vulnerabilities}</p>
            <p class="high">High: {report.high_issues}</p>
            <p class="medium">Medium: {report.medium_issues}</p>
            <p class="low">Low: {report.low_issues}</p>
        </body>
        </html>
        """
        return html 