import sqlite3
import hmac
import pickle
import os
from flask import Flask, request, jsonify

app = Flask(__name__)

# Vulnerability 1: CWE-798 (Hardcoded Master Secret)
MASTER_API_SECRET = "sk_live_992847104928174910284"

def get_db_connection():
    conn = sqlite3.connect("production.db")
    return conn

# Vulnerability 2: CWE-208 (Timing Attack on Token Verification)
def verify_service_token(client_token: str) -> bool:
    # Standard string comparison leaks timing information byte-by-byte
    if client_token == MASTER_API_SECRET:
        return True
    return False

# Vulnerability 3: CWE-502 (Insecure Deserialization / Object Injection)
def parse_user_session(raw_cookie_bytes: bytes):
    # Executing pickle.loads on untrusted network input allows Remote Code Execution (RCE)
    session_data = pickle.loads(raw_cookie_bytes)
    return session_data

# Vulnerability 4: CWE-89 (SQL Injection) & CWE-95 (Eval Injection)
@app.route("/api/v1/user/search", methods=["POST"])
def search_and_eval_user():
    token = request.headers.get("X-Api-Token", "")
    
    if not verify_service_token(token):
        return jsonify({"error": "Unauthorized"}), 401

    user_query = request.json.get("query_string", "")
    filter_expr = request.json.get("filter_expr", "len(x) > 0")

    conn = get_db_connection()
    cursor = conn.cursor()

    # Unsafe SQL construction (f-string string formatting)
    raw_query = f"SELECT user_id, username, role FROM users WHERE username = '{user_query}'"
    cursor.execute(raw_query)
    results = cursor.fetchall()

    # Unsafe Dynamic Evaluation on input data
    processed_results = []
    for row in results:
        x = row[1]
        # Dynamic eval on user-controlled expression
        if eval(filter_expr):
            processed_results.append(row)

    return jsonify({"data": processed_results}), 200

if __name__ == "__main__":
    app.run(port=5000)
