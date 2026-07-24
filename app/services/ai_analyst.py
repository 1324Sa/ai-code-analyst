import json
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional

class AIAnalystService:
    @staticmethod
    def evaluate_analysis(
        language: str, 
        structure: Dict[str, Any], 
        data_flow: List[Dict[str, str]], 
        ollama_url: Optional[str] = None
    ) -> Dict[str, Any]:
        
        # 1. Base Static Heuristics Engine
        heuristic_warnings = []
        optimizations = []

        for node in data_flow:
            if node.get("type") == "FUNCTION_ARGUMENT" and "console.log" in node.get("to", ""):
                heuristic_warnings.append(
                    f"Information Exposure Risk: Argument '{node.get('from')}' is output directly via console log in function '{node.get('scope')}'."
                )
            if node.get("type") == "FUNCTION_ARGUMENT" and "print" in node.get("to", ""):
                heuristic_warnings.append(
                    f"Sensitive Logging Warning: Variable '{node.get('from')}' is directly printed in function '{node.get('scope')}'."
                )

        for func_name, meta in structure.items():
            if not meta.get("variables") and not meta.get("calls"):
                optimizations.append(
                    f"Function '{func_name}' has no internal state or side effects. Consider simplifying or inlining."
                )

        base_summary = {
            "status": "SECURE" if not heuristic_warnings else "NEEDS_REVIEW",
            "metrics": {
                "functions_analyzed": len(structure),
                "data_flow_edges": len(data_flow)
            },
            "heuristic_warnings": heuristic_warnings,
            "heuristic_optimizations": optimizations,
            "llm_insights": None
        }

        # 2. Optional LLM Integration (Ollama Local Instance)
        if ollama_url:
            llm_response = AIAnalystService._query_ollama(ollama_url, language, structure, data_flow)
            base_summary["llm_insights"] = llm_response

        return base_summary

    @staticmethod
    def _query_ollama(url: str, language: str, structure: Dict[str, Any], data_flow: List[Dict[str, str]]) -> Dict[str, Any]:
        prompt = f"""You are an expert static code analyst and security auditor.
Analyze the following parsed AST representation of a {language} program:

--- STRUCTURE ---
{json.dumps(structure, indent=2)}

--- DATA FLOW GRAPH ---
{json.dumps(data_flow, indent=2)}

Provide concise insights covering:
1. Potential security vulnerabilities or data leaks.
2. Code refactoring and performance optimizations.
3. High-level execution overview.
"""
        payload = {
            "model": "qwen2.5-coder",  # Default local model fallback
            "prompt": prompt,
            "stream": False
        }

        try:
            req = urllib.request.Request(
                f"{url.rstrip('/')}/api/generate",
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                result = json.loads(resp.read().decode("utf-8"))
                return {"llm_analysis": result.get("response", "No response from model.")}
        except urllib.error.URLError as e:
            return {"error": f"Failed to connect to local LLM service: {str(e)}"}
        except Exception as e:
            return {"error": f"LLM execution error: {str(e)}"}
