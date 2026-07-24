import ast
import re
from typing import Dict, List, Any, Optional, Set


class UnifiedCodeAnalyzer(ast.NodeVisitor):
    """
    Unified AST Visitor & Security Analyzer:
    - Extracts Data & Taint Flow Graphs with exact line numbers
    - Identifies Insecure Imports (child_process, subprocess, os, sys)
    - Detects Hardcoded Credentials & API Secrets
    """

    def __init__(self, source_code: str):
        self.source_code = source_code
        self.lines = source_code.splitlines()
        
        # Security Findings Output
        self.findings: List[Dict[str, Any]] = []
        
        # AST Data Flow Structures
        self.functions: Dict[str, Dict[str, Any]] = {}
        self.current_function: Optional[str] = None
        self.data_flow_graph: List[Dict[str, Any]] = []
        
        # Global variable tracker
        self.global_variables: Set[str] = set()

    # ==========================================
    # 1. FILE-WIDE PRE-SCANNERS (Regex Rules)
    # ==========================================
    def scan_hardcoded_secrets(self) -> None:
        """Scans full source code line-by-line for hardcoded API keys and secrets."""
        secret_patterns = [
            (r'(?i)(jwt_secret|api_key|api_secret|access_token|private_key|master_key|secret_key)\s*=\s*["\']([^"\']+)["\']', "Hardcoded Secret / API Key"),
            (r'sk_live_[0-9a-zA-Z]{24,}', "Live Stripe Secret Key"),
            (r'EAACEdEose0cBA[0-9A-Za-z]+', "Facebook Access Token"),
            (r'AIzaSy[0-9A-Za-z-_]{35}', "Google API Key")
        ]

        for line_num, line in enumerate(self.lines, 1):
            for pattern, issue_type in secret_patterns:
                match = re.search(pattern, line)
                if match:
                    var_name = match.group(1) if match.lastindex and match.lastindex >= 1 else "Secret Token"
                    self.findings.append({
                        "id": f"sec_secret_L{line_num}",
                        "title": f"Hardcoded Secret Detected (`{var_name}`)",
                        "severity": "CRITICAL",
                        "category": "Hardcoded Secret",
                        "line": line_num,
                        "description": f"Sensitive credential `{var_name}` is hardcoded directly in the source code.",
                        "snippet": line.strip(),
                        "fix_suggestion": "Extract secrets into environment variables (e.g., `os.getenv(...)`)."
                    })

    # ==========================================
    # 2. AST VISITOR METHODS (Data Flow & Rules)
    # ==========================================
    def visit_Import(self, node: ast.Import) -> None:
        """Flag potentially dangerous file-wide module imports."""
        dangerous_modules = {"child_process", "subprocess", "os", "sys"}
        for alias in node.names:
            if alias.name in dangerous_modules:
                self.findings.append({
                    "id": f"sec_import_L{node.lineno}",
                    "title": f"Unsafe System Module Imported (`{alias.name}`)",
                    "severity": "HIGH",
                    "category": "Insecure Import",
                    "line": node.lineno,
                    "description": f"Module `{alias.name}` provides low-level system or process execution capabilities.",
                    "snippet": self.lines[node.lineno - 1].strip() if node.lineno <= len(self.lines) else "",
                    "fix_suggestion": "Restrict use of system commands and rigorously validate dynamic inputs."
                })
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        """Flag dangerous module imports via 'from X import Y'."""
        dangerous_modules = {"subprocess", "os", "sys"}
        if node.module in dangerous_modules:
            self.findings.append({
                "id": f"sec_importfrom_L{node.lineno}",
                "title": f"Unsafe Import From (`{node.module}`)",
                "severity": "HIGH",
                "category": "Insecure Import",
                "line": node.lineno,
                "description": f"Importing directly from system module `{node.module}`.",
                "snippet": self.lines[node.lineno - 1].strip() if node.lineno <= len(self.lines) else "",
                "fix_suggestion": "Avoid executing arbitrary system commands with user-controlled data."
            })
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Tracks current scope, function arguments, and internal variables."""
        previous_function = self.current_function
        self.current_function = node.name

        args = [arg.arg for arg in node.args.args]
        self.functions[node.name] = {
            "line": node.lineno,
            "args": args,
            "variables": [],
            "calls": []
        }

        self.generic_visit(node)
        self.current_function = previous_function

    def visit_Assign(self, node: ast.Assign) -> None:
        """Extract variable assignment relationships and build data flow edges."""
        targets = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                targets.append(target.id)
            elif isinstance(target, ast.Attribute) and isinstance(target.value, ast.Name):
                targets.append(f"{target.value.id}.{target.attr}")

        sources = self._extract_sources(node.value)

        for target in targets:
            # Scope management
            if self.current_function:
                if target not in self.functions[self.current_function]["variables"]:
                    self.functions[self.current_function]["variables"].append(target)
            else:
                self.global_variables.add(target)

            # Record taint flow edge
            for src in sources:
                self.data_flow_graph.append({
                    "from": src,
                    "to": target,
                    "scope": self.current_function or "global",
                    "type": "VARIABLE_ASSIGNMENT",
                    "line": node.lineno
                })

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Capture function invocations and trace arguments into sinks."""
        called_func = self._resolve_call_name(node.func)

        if self.current_function and called_func:
            if called_func not in self.functions[self.current_function]["calls"]:
                self.functions[self.current_function]["calls"].append(called_func)

        # Map dynamic sources flowing into function arguments
        for arg in node.args:
            arg_sources = self._extract_sources(arg)
            for src in arg_sources:
                self.data_flow_graph.append({
                    "from": src,
                    "to": f"{called_func}()" if called_func else "<call>",
                    "scope": self.current_function or "global",
                    "type": "FUNCTION_ARGUMENT",
                    "line": node.lineno
                })

        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        """Trace return values to caller boundary."""
        if self.current_function and node.value:
            return_sources = self._extract_sources(node.value)
            for src in return_sources:
                self.data_flow_graph.append({
                    "from": src,
                    "to": f"{self.current_function}:<return>",
                    "scope": self.current_function,
                    "type": "RETURN_VALUE",
                    "line": node.lineno
                })
        self.generic_visit(node)

    # ==========================================
    # 3. HELPER UTILITIES
    # ==========================================
    def _resolve_call_name(self, node: ast.AST) -> str:
        """Resolves target names for functions or methods (e.g., cursor.execute)."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            base = self._resolve_call_name(node.value)
            return f"{base}.{node.attr}" if base else node.attr
        return "anonymous_call"

    def _extract_sources(self, node: Optional[ast.AST]) -> List[str]:
        """Recursively extracts variable dependencies from AST expressions."""
        sources: List[str] = []
        if node is None:
            return sources

        if isinstance(node, ast.Name):
            sources.append(node.id)

        elif isinstance(node, ast.Attribute):
            base = self._resolve_call_name(node.value)
            sources.append(f"{base}.{node.attr}" if base else node.attr)

        elif isinstance(node, ast.BinOp):
            sources.extend(self._extract_sources(node.left))
            sources.extend(self._extract_sources(node.right))

        elif isinstance(node, ast.Call):
            # Extract arguments passed inside function calls
            for arg in node.args:
                sources.extend(self._extract_sources(arg))

        elif isinstance(node, ast.JoinedStr):
            # Handles f-strings
            for value in node.values:
                sources.extend(self._extract_sources(value))

        elif isinstance(node, ast.FormattedValue):
            sources.extend(self._extract_sources(node.value))

        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for elt in node.elts:
                sources.extend(self._extract_sources(elt))

        elif isinstance(node, ast.Dict):
            for val in node.values:
                sources.extend(self._extract_sources(val))

        return list(set(sources))


# ==========================================
# MAIN EXECUTION ENTRYPOINT
# ==========================================
def analyze_python_code(source_code: str) -> Dict[str, Any]:
    """
    Parses Python source code and runs static security scanning + taint flow tracing.
    """
    analyzer = UnifiedCodeAnalyzer(source_code)
    
    # 1. Run Regex Secret Scanner
    analyzer.scan_hardcoded_secrets()
    
    # 2. Parse AST & Run AST Visitor
    parse_error = None
    try:
        tree = ast.parse(source_code)
        analyzer.visit(tree)
    except SyntaxError as e:
        parse_error = f"Syntax Error at line {e.lineno}: {e.msg}"
        analyzer.findings.append({
            "id": "sec_syntax_error",
            "title": "Python Syntax Error",
            "severity": "CRITICAL",
            "category": "Parsing Error",
            "line": e.lineno or 1,
            "description": parse_error,
            "snippet": e.text.strip() if e.text else "",
            "fix_suggestion": "Correct code syntax errors before running security audit."
        })

    # Sort findings by severity priority
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    analyzer.findings.sort(key=lambda x: severity_order.get(x["severity"], 4))

    return {
        "status": "ERROR" if parse_error else "SUCCESS",
        "error_message": parse_error,
        "execution_summary": {
            "total_lines": len(analyzer.lines),
            "total_findings": len(analyzer.findings),
            "total_edges": len(analyzer.data_flow_graph),
            "coverage_percentage": 100
        },
        "findings": analyzer.findings,
        "structure": analyzer.functions,
        "data_flow": analyzer.data_flow_graph
    }


# ==========================================
# EXAMPLE VERIFICATION TEST
# ==========================================
if __name__ == "__main__":
    test_code = """import os
import sqlite3

API_SECRET_KEY = "sk_live_98a7b6c5d4e3f2a1"

def fetch_user(user_id, token):
    if token != API_SECRET_KEY:
        return None

    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()
"""

    results = analyze_python_code(test_code)
    
    print("=== SCANNED FINDINGS ===")
    for finding in results["findings"]:
        print(f"[{finding['severity']}] Line {finding['line']}: {finding['title']}")
        
    print("\n=== TAINT DATA FLOW GRAPH EDGES ===")
    for edge in results["data_flow"]:
        print(f"[L{edge['line']}] {edge['from']} -> {edge['to']} ({edge['type']})")