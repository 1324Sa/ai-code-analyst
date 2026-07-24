from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional

class CodeAnalysisRequest(BaseModel):
    code: str = Field(..., description="Source code to analyze")
    language: str = Field(..., description="Programming language (python, javascript, c, cpp, java)")
    ollama_url: Optional[str] = Field(None, description="Optional local Ollama base URL (e.g. http://localhost:11434)")

class AnalysisResponse(BaseModel):
    language: str
    structure: Dict[str, Any]
    data_flow: List[Dict[str, Any]]
    execution_summary: Optional[Dict[str, Any]] = None
