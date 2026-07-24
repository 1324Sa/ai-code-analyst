import ast
import re
from typing import Dict, List, Any

class AdvancedSecurityAnalyzer(ast.NodeVisitor):
    def __init__(self, source_code: str):
        self.source_code = source_code
        self.lines = source_code.splitlines()
        self.findings: List[Dict[str, Any]] = []

    # 1. Detect CWE-208: Timing Attack on Secret Comparison
    def visit_Compare(self, node: ast.Compare):
        # Look for '==' comparisons involving secret-like variable names
        is_equality = any(isinstance(op, ast.Eq) for op in node.ops)
        if is_equality:
            all_comparators = [node.left] + node.comparators
            has_secret_var = False

            for comp in all_comparators:
                if isinstance(comp, ast.Name) and re.search(r'(secret|key|token|auth|password)', comp.id, re.I):
                    has_secret_var = True

            if has_secret_var:
                self.findings.append({
                    "id": f"sec_timing_attack_L{node.lineno}",
                    "title": "Timing Attack Vulnerability (Observable Timing Discrepancy)",
                    "severity": "HIGH",
                    "category": "Authentication Bypass",
                    "cwe": "CWE-208",
                    "pci_dss": "PCI-DSS v4.0 6.2.4",
                    "nist": "NIST SP 800-53 IA-5",
                    "line": node.lineno,
                    "description": "Using standard equality (`==`) for secret comparisons is susceptible to timing attacks. Execution time leaks information about secret bytes.",
                    "snippet": self.lines[node.lineno - 1].strip() if node.lineno <= len(self.lines) else "",
                    "fix_suggestion": "Use `hmac.compare_digest()` for constant-time comparison."
                })

        self.generic_visit(node)

    # 2. Whole-File SQL Injection Detection (f-strings / String formatting)
    def visit_Call(self, node: ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        # Check cursor.execute(...) calls across the whole file
        if func_name == "execute":
            for arg in node.args:
                is_unsafe_sql = False
                # Detect f-string argument or binop string concatenation inside execute()
                if isinstance(arg, (ast.JoinedStr, ast.BinOp)):
                    is_unsafe_sql = True
                elif isinstance(arg, ast.Name):
                    # Direct check if named variable holds an unparameterized SQL query
                    is_unsafe_sql = True  

                if is_unsafe_sql:
                    self.findings.append({
                        "id": f"sec_sqli_L{node.lineno}",
                        "title": "SQL Injection (Unparameterized Query)",
                        "severity": "CRITICAL",
                        "category": "Injection",
                        "cwe": "CWE-89",
                        "pci_dss": "PCI-DSS v4.0 6.2.4",
                        "nist": "NIST SP 800-53 SI-10",
                        "line": node.lineno,
                        "description": "Raw string concatenation passed to database execution context.",
                        "snippet": self.lines[node.lineno - 1].strip() if node.lineno <= len(self.lines) else "",
                        "fix_suggestion": "Use parameterized queries (e.g., `cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))`)."
                    })

        self.generic_visit(node)


def analyze_code(source_code: str) -> List[Dict[str, Any]]:
    """Helper function to parse Python code and return security findings."""
    try:
        tree = ast.parse(source_code)
        analyzer = AdvancedSecurityAnalyzer(source_code)
        analyzer.visit(tree)
        return analyzer.findings
    except SyntaxError as e:
        return [{
            "id": "syntax_error",
            "title": "Syntax Error",
            "severity": "LOW",
            "category": "Parse Error",
            "line": e.lineno or 1,
            "description": f"Failed to parse source code: {str(e)}",
            "snippet": "",
            "fix_suggestion": "Correct the syntax error to enable AST scanning."
        }]
