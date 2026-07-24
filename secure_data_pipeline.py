import os
import subprocess
import hashlib
import tempfile
from flask import Flask, request, jsonify

app = Flask(__name__)

# Vulnerability 1: CWE-327 (Use of Weak Cryptographic Hash - MD5)
def generate_file_checksum(file_content: bytes) -> str:
    # MD5 is cryptographically broken and vulnerable to collision attacks
    hasher = hashlib.md5()
    hasher.update(file_content)
    return hasher.hexdigest()

# Vulnerability 2: CWE-22 (Path Traversal / Unsanitized File Access)
def read_user_log_file(filename: str) -> str:
    # Directory Traversal allows arbitrary file reading (e.g. filename = "../../../etc/passwd")
    filepath = os.path.join("/var/log/app/", filename)
    with open(filepath, "r") as f:
        return f.read()

# Vulnerability 3: CWE-78 (OS Command Injection)
@app.route("/api/v1/system/convert", methods=["POST"])
def convert_user_document():
    doc_name = request.json.get("document_name", "")
    output_format = request.json.get("format", "pdf")

    # Command injection via shell=True and unsanitized string formatting
    command = f"pandoc /tmp/uploads/{doc_name} -o /tmp/outputs/{doc_name}.{output_format}"
    
    # Unsafe execution context
    result = subprocess.check_output(command, shell=True)
    return jsonify({"status": "success", "output": result.decode("utf-8")}), 200

# Vulnerability 4: CWE-377 (Insecure Temporary File Creation)
def save_temporary_data(payload: str):
    # Insecure temporary file creation exposes sensitive data in multi-user systems
    temp_path = f"/tmp/user_data_{os.getpid()}.tmp"
    with open(temp_path, "w") as f:
        f.write(payload)
    return temp_path

if __name__ == "__main__":
    app.run(port=5001)
