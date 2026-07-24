import re
from typing import Dict, List, Any

def parse_cpp_java_data_flow(source_code: str, language: str) -> Dict[str, Any]:
    structure = {}
    data_flow = []

    # 1. Regex Match Function Declarations (C++ & Java)
    # Matches: void funcName(int x, String y) { ... }
    func_pattern = re.compile(
        r'(?:public|private|protected|static|inline|\s)*[\w<>\*]+\s+([a-zA-Z_]\w*)\s*\(([^)]*)\)\s*\{'
    )

    # Find function matches and their byte locations
    matches = list(func_pattern.finditer(source_code))

    for i, match in enumerate(matches):
        func_name = match.group(1)
        raw_args = match.group(2).strip()

        # Ignore keywords that look like function declarations
        if func_name in ("if", "while", "for", "switch", "catch"):
            continue

        # Extract arguments
        args = []
        if raw_args:
            for arg_pair in raw_args.split(','):
                tokens = arg_pair.strip().split()
                if tokens:
                    # Clean parameter name from pointers or references
                    param_name = tokens[-1].lstrip('*&')
                    args.append(param_name)

        # Extract function body block
        start_idx = match.end()
        end_idx = matches[i + 1].start() if i + 1 < len(matches) else len(source_code)
        body = source_code[start_idx:end_idx]

        variables = []
        calls = []

        # 2. Extract Variable Declarations & Assignments inside body
        # Matches: int c = a + b; or String data = input;
        assign_pattern = re.compile(r'(?:[\w<>\*]+\s+)?([a-zA-Z_]\w*)\s*=\s*([^;]+);')
        for assign in assign_pattern.finditer(body):
            target = assign.group(1)
            expr = assign.group(2)

            if target not in variables and target not in ("if", "return"):
                variables.append(target)

            # Find source variables used in expression
            sources = re.findall(r'\b[a-zA-Z_]\w*\b', expr)
            for src in sources:
                if src in args or src in variables:
                    data_flow.append({
                        "from": src,
                        "to": target,
                        "scope": func_name,
                        "type": "VARIABLE_ASSIGNMENT"
                    })

        # 3. Extract Function Calls inside body
        # Matches: std::cout << c; or printf(c); or System.out.println(c);
        call_pattern = re.compile(r'([a-zA-Z_]\w*(?:\::[a-zA-Z_]\w*)*(?:\.[a-zA-Z_]\w*)*)\s*\(([^)]*)\)')
        for call in call_pattern.finditer(body):
            called_func = call.group(1)
            call_args = call.group(2)

            if called_func not in calls and called_func not in ("if", "while", "for"):
                calls.append(called_func)

            # Check variables passed as arguments
            arg_tokens = re.findall(r'\b[a-zA-Z_]\w*\b', call_args)
            for arg_var in arg_tokens:
                if arg_var in args or arg_var in variables:
                    data_flow.append({
                        "from": arg_var,
                        "to": f"{called_func}()",
                        "scope": func_name,
                        "type": "FUNCTION_ARGUMENT"
                    })

        structure[func_name] = {
            "args": args,
            "variables": variables,
            "calls": calls
        }

    return {
        "structure": structure,
        "data_flow": data_flow
    }
