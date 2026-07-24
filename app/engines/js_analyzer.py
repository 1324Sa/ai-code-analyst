import esprima
from typing import Dict, List, Any

def parse_javascript_data_flow(source_code: str) -> Dict[str, Any]:
    tree = esprima.parseScript(source_code, {'tolerant': True, 'loc': True})
    
    functions = {}
    data_flow = []

    def traverse(node, scope_func=None):
        if not node or not hasattr(node, 'type'):
            return

        current_func = scope_func

        # Track Function Declarations
        if node.type == 'FunctionDeclaration':
            func_name = node.id.name
            args = [param.name for param in node.params if param.type == 'Identifier']
            functions[func_name] = {
                "args": args,
                "variables": [],
                "calls": []
            }
            current_func = func_name

        # Track Variable Declarations (const, let, var)
        elif node.type == 'VariableDeclarator' and current_func:
            if node.id.type == 'Identifier':
                var_name = node.id.name
                if var_name not in functions[current_func]["variables"]:
                    functions[current_func]["variables"].append(var_name)
                
                # Check source assignment
                if node.init and node.init.type == 'Identifier':
                    data_flow.append({
                        "from": node.init.name,
                        "to": var_name,
                        "scope": current_func,
                        "type": "VARIABLE_ASSIGNMENT"
                    })

        # Track Function Calls
        elif node.type == 'CallExpression' and current_func:
            callee_name = ""
            if node.callee.type == 'Identifier':
                callee_name = node.callee.name
            elif node.callee.type == 'MemberExpression':
                callee_name = f"{node.callee.object.name}.{node.callee.property.name}" if hasattr(node.callee.object, 'name') else node.callee.property.name

            if callee_name and callee_name not in functions[current_func]["calls"]:
                functions[current_func]["calls"].append(callee_name)

            for arg in node.arguments:
                if arg.type == 'Identifier':
                    data_flow.append({
                        "from": arg.name,
                        "to": f"{callee_name}()",
                        "scope": current_func,
                        "type": "FUNCTION_ARGUMENT"
                    })

        # Recursively traverse child properties
        for key in dir(node):
            if key.startswith('_') or key in ('type', 'loc'):
                continue
            val = getattr(node, key, None)
            if isinstance(val, list):
                for item in val:
                    if hasattr(item, 'type'):
                        traverse(item, current_func)
            elif hasattr(val, 'type'):
                traverse(val, current_func)

    traverse(tree)

    return {
        "structure": functions,
        "data_flow": data_flow
    }
