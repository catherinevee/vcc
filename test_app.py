#!/usr/bin/env python3
"""
Basic tests for the Vibe-Code Detector application
"""

import unittest
import tempfile
import os
import sys
from pathlib import Path

# Add the current directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vibe_code_detector import VibeCodeAnalyzer, ReportFormatter, Finding, AnalysisReport

class TestVibeCodeDetector(unittest.TestCase):
    """Test cases for the Vibe-Code Detector"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.analyzer = VibeCodeAnalyzer()
        self.temp_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Clean up test fixtures"""
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_analyzer_initialization(self):
        """Test that the analyzer initializes correctly"""
        self.assertIsNotNone(self.analyzer)
        self.assertIsInstance(self.analyzer.file_extensions, set)
        self.assertIn('.py', self.analyzer.file_extensions)
        self.assertIn('.js', self.analyzer.file_extensions)
    
    def test_finding_creation(self):
        """Test creating a Finding object"""
        finding = Finding(
            file_path="test.py",
            line_number=10,
            description="Test finding",
            severity="Medium",
            category="Code Quality",
            fix_suggestion="Fix this issue",
            confidence=0.8
        )
        
        self.assertEqual(finding.file_path, "test.py")
        self.assertEqual(finding.line_number, 10)
        self.assertEqual(finding.severity, "Medium")
        self.assertEqual(finding.confidence, 0.8)
    
    def test_analyze_python_file_with_issues(self):
        """Test analyzing a Python file with known issues"""
        # Create a test Python file with issues
        test_file = os.path.join(self.temp_dir, "test.py")
        with open(test_file, 'w') as f:
            f.write("""
# Test file with issues
password = "secret123"  # Hardcoded password
print("Debug info")     # Print statement
try:
    pass
except:                # Broad exception
    pass
# TODO: Fix this later
""")
        
        # Analyze the file
        self.analyzer._analyze_file(test_file, self.temp_dir)
        
        # Check that findings were created
        self.assertGreater(len(self.analyzer.findings), 0)
        
        # Check for specific issues
        finding_descriptions = [f.description for f in self.analyzer.findings]
        self.assertIn("Hardcoded password", finding_descriptions)
        self.assertIn("Print statement found", finding_descriptions)
        self.assertIn("Broad exception handling", finding_descriptions)
        self.assertIn("TODO comment found", finding_descriptions)
    
    def test_analyze_javascript_file_with_issues(self):
        """Test analyzing a JavaScript file with known issues"""
        # Create a test JavaScript file with issues
        test_file = os.path.join(self.temp_dir, "test.js")
        with open(test_file, 'w') as f:
            f.write("""
// Test JavaScript file with issues
const apiKey = "secret_key_123";  // Hardcoded API key
console.log("Debug info");        // Console.log statement
eval("some code");                // Eval usage
// FIXME: Fix this later
""")
        
        # Analyze the file
        self.analyzer._analyze_file(test_file, self.temp_dir)
        
        # Check that findings were created
        self.assertGreater(len(self.analyzer.findings), 0)
        
        # Check for specific issues
        finding_descriptions = [f.description for f in self.analyzer.findings]
        self.assertIn("Hardcoded API key", finding_descriptions)
        self.assertIn("Console.log statement found", finding_descriptions)
        self.assertIn("Eval usage found", finding_descriptions)
        self.assertIn("FIXME comment found", finding_descriptions)
    
    def test_report_generation(self):
        """Test generating an analysis report"""
        # Create some test findings
        findings = [
            Finding(
                file_path="test.py",
                line_number=5,
                description="Test finding 1",
                severity="Critical",
                category="Security",
                fix_suggestion="Fix this",
                confidence=0.9
            ),
            Finding(
                file_path="test.py",
                line_number=10,
                description="Test finding 2",
                severity="Medium",
                category="Code Quality",
                fix_suggestion="Fix that",
                confidence=0.7
            )
        ]
        
        # Create a report
        report = AnalysisReport(
            repository="test-repo",
            timestamp="2024-01-01T00:00:00",
            vibe_coding_score=75,
            technical_debt_hours=10,
            critical_vulnerabilities=1,
            high_issues=0,
            medium_issues=1,
            low_issues=0,
            findings=findings,
            summary="Test summary",
            recommendations=["Fix critical issues"]
        )
        
        # Test report properties
        self.assertEqual(report.repository, "test-repo")
        self.assertEqual(report.vibe_coding_score, 75)
        self.assertEqual(report.critical_vulnerabilities, 1)
        self.assertEqual(len(report.findings), 2)
        self.assertEqual(len(report.recommendations), 1)
    
    def test_report_formatter_json(self):
        """Test JSON report formatting"""
        # Create a simple report
        findings = [
            Finding(
                file_path="test.py",
                line_number=5,
                description="Test finding",
                severity="High",
                category="Security",
                fix_suggestion="Fix this",
                confidence=0.8
            )
        ]
        
        report = AnalysisReport(
            repository="test-repo",
            timestamp="2024-01-01T00:00:00",
            vibe_coding_score=80,
            technical_debt_hours=5,
            critical_vulnerabilities=0,
            high_issues=1,
            medium_issues=0,
            low_issues=0,
            findings=findings,
            summary="Test summary",
            recommendations=[]
        )
        
        # Format as JSON
        json_output = ReportFormatter.to_json(report)
        
        # Check that it's valid JSON
        import json
        parsed = json.loads(json_output)
        self.assertEqual(parsed['repository'], 'test-repo')
        self.assertEqual(parsed['vibe_coding_score'], 80)
        self.assertEqual(len(parsed['findings']), 1)
    
    def test_report_formatter_markdown(self):
        """Test Markdown report formatting"""
        # Create a simple report
        findings = [
            Finding(
                file_path="test.py",
                line_number=5,
                description="Test finding",
                severity="Medium",
                category="Code Quality",
                fix_suggestion="Fix this",
                confidence=0.7
            )
        ]
        
        report = AnalysisReport(
            repository="test-repo",
            timestamp="2024-01-01T00:00:00",
            vibe_coding_score=85,
            technical_debt_hours=3,
            critical_vulnerabilities=0,
            high_issues=0,
            medium_issues=1,
            low_issues=0,
            findings=findings,
            summary="Test summary",
            recommendations=["Fix medium issues"]
        )
        
        # Format as Markdown
        markdown_output = ReportFormatter.to_markdown(report)
        
        # Check that it contains expected content
        self.assertIn("# Vibe-Code Analysis Report", markdown_output)
        self.assertIn("test-repo", markdown_output)
        self.assertIn("85/100", markdown_output)
        self.assertIn("Medium Issues", markdown_output)
        self.assertIn("Test finding", markdown_output)

if __name__ == '__main__':
    # Run the tests
    unittest.main(verbosity=2) 