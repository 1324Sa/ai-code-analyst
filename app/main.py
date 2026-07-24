import ast
import re
from fastapi import FastAPI, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

app = FastAPI(title="AI Code Analyst Engine")
templates = Jinja2Templates(directory="templates")

class AnalyzeRequest(BaseModel):
    code: str
    language: Optional[str] = "Python"
    security_profile: Optional[str] = "OWASP Top 10"
    use_case: Optional[str] = "Authentication Service"
    suggestion_focus: Optional[str] = "Security Focus"

class PythonDataFlowVisitor(ast.NodeVisitor):
    def __init__(self):
        self.edges: List[Dict[str, Any]] = []
        self.hardcoded_secrets: List[Dict[str, Any]] = []

    def visit_Assign(self, node: ast.Assign):
        line = node.lineno
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                # Check secrets
                if any(s in var_name.lower() for s in ["token", "key", "secret", "password", "card", "credential"]):
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        self.hardcoded_secrets.append({"var_name": var_name, "line": line})

                # Flow tracing: var_to = var_from
                if isinstance(node.value, ast.Name):
                    self.edges.append({
                        "from": node.value.id,
                        "to": var_name,
                        "type": "VARIABLE_ASSIGNMENT",
                        "line": line
                    })
                elif isinstance(node.value, ast.Call):
                    if isinstance(node.value.func, ast.Name):
                        func_name = node.value.func.id
                        self.edges.append({
                            "from": func_name,
                            "to": var_name,
                            "type": "RETURN_ASSIGNMENT",
                            "line": line
                        })
                        for arg in node.value.args:
                            if isinstance(arg, ast.Name):
                                self.edges.append({
                                    "from": arg.id,
                                    "to": f"{func_name}()",
                                    "type": "FUNCTION_ARGUMENT",
                                    "line": line
                                })
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        line = node.lineno
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            for arg in node.args:
                if isinstance(arg, ast.Name):
                    self.edges.append({
                        "from": arg.id,
                        "to": f"{func_name}()",
                        "type": "FUNCTION_ARGUMENT",
                        "line": line
                    })
        self.generic_visit(node)

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.post("/api/v1/analyze")
async def analyze_code(req: AnalyzeRequest):
    edges = []
    secrets = []
    
    if req.language.lower() == "python":
        try:
            tree = ast.parse(req.code)
            visitor = PythonDataFlowVisitor()
            visitor.visit(tree)
            edges = visitor.edges
            secrets = visitor.hardcoded_secrets
        except SyntaxError as e:
            return {"status": "ERROR", "error_message": f"Syntax Error on line {e.lineno}: {e.msg}"}
    else:
        # Generic Regex Extractor with Line Numbers
        lines = req.code.split("\n")
        assign_pat = re.compile(r'(?:(?:auto|int|double|float|char|const|let|var)\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*([a-zA-Z_][a-zA-Z0-9_]*)')
        func_pat = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\)')
        
        for idx, line in enumerate(lines, start=1):
            m = assign_pat.search(line)
            if m and m.group(2) not in ["new", "return", "if", "else", "true", "false"]:
                edges.append({"from": m.group(2), "to": m.group(1), "type": "VARIABLE_ASSIGNMENT", "line": idx})
            fm = func_pat.search(line)
            if fm and fm.group(1) not in ["if", "while", "for", "switch"]:
                edges.append({"from": fm.group(2), "to": f"{fm.group(1)}()", "type": "FUNCTION_ARGUMENT", "line": idx})

    return {
        "status": "SUCCESS",
        "data_flow": edges,
        "findings": [
            {
                "severity": "Critical" if secrets else "High",
                "category": "CWE-798: Hardcoded Secrets" if secrets else "PCI-DSS Requirement 3",
                "title": f"Hardcoded secret in `{secrets[0]['var_name']}`" if secrets else "Data Sanitization Warning",
                "description": f"Found sensitive data handling on line {secrets[0]['line']}" if secrets else "Pass input through sanitizer.",
                "line": secrets[0]['line'] if secrets else 1
            }
        ],
        "execution_summary": {
            "language": req.language,
            "security_profile": req.security_profile,
            "use_case": req.use_case,
            "total_edges": len(edges),
            "total_findings": 1
        }
    }