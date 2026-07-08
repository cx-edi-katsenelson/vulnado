"""
vulnerable_test_app.py

INTENTIONALLY VULNERABLE CODE - FOR SECURITY SCANNER TESTING ONLY.
Do NOT deploy, run against real data, or use in production.
Each function below demonstrates one common vulnerability class (roughly
mapped to OWASP Top 10 / CWE categories) so you can verify a SAST tool
catches them.
"""

import os
import sqlite3
import subprocess
import pickle
import hashlib
import xml.etree.ElementTree as ET
import yaml
from flask import Flask, request, redirect

app = Flask(__name__)

# ---------------------------------------------------------------------------
# 1. SQL Injection (CWE-89)
# ---------------------------------------------------------------------------
@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id  # unsanitized input
    cursor.execute(query)
    return str(cursor.fetchall())


# ---------------------------------------------------------------------------
# 2. Command Injection (CWE-78)
# ---------------------------------------------------------------------------
@app.route("/ping")
def ping_host():
    host = request.args.get("host")
    result = os.system("ping -c 1 " + host)  # shell command built from input
    return str(result)


# ---------------------------------------------------------------------------
# 3. Insecure Deserialization (CWE-502)
# ---------------------------------------------------------------------------
@app.route("/load")
def load_data():
    raw = request.args.get("data").encode()
    obj = pickle.loads(raw)  # deserializing untrusted data
    return str(obj)


# ---------------------------------------------------------------------------
# 4. Hardcoded Credentials / Secrets (CWE-798)
# ---------------------------------------------------------------------------
DB_PASSWORD = "SuperSecret123!"
API_KEY = "sk-live-abcdef1234567890"


def connect_to_service():
    return f"connecting with key {API_KEY} and password {DB_PASSWORD}"


# ---------------------------------------------------------------------------
# 5. Weak Cryptographic Hash (CWE-327 / use of MD5 for passwords)
# ---------------------------------------------------------------------------
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # MD5 is broken for this use


# ---------------------------------------------------------------------------
# 6. Path Traversal (CWE-22)
# ---------------------------------------------------------------------------
@app.route("/download")
def download_file():
    filename = request.args.get("file")
    path = "/var/app/files/" + filename  # no sanitization, allows ../../etc/passwd
    with open(path, "rb") as f:
        return f.read()


# ---------------------------------------------------------------------------
# 7. Server-Side Request Forgery / Open Redirect (CWE-601)
# ---------------------------------------------------------------------------
@app.route("/redirect")
def open_redirect():
    target = request.args.get("url")
    return redirect(target)  # unvalidated redirect target


# ---------------------------------------------------------------------------
# 8. XML External Entity Injection (CWE-611)
# ---------------------------------------------------------------------------
@app.route("/parse_xml", methods=["POST"])
def parse_xml():
    xml_data = request.data
    parser = ET.XMLParser()  # default parser, no entity resolution disabled
    tree = ET.fromstring(xml_data, parser=parser)
    return str(tree)


# ---------------------------------------------------------------------------
# 9. Unsafe YAML Load (CWE-502 variant)
# ---------------------------------------------------------------------------
@app.route("/config", methods=["POST"])
def load_config():
    config_data = request.data
    config = yaml.load(config_data, Loader=yaml.Loader)  # unsafe loader
    return str(config)


# ---------------------------------------------------------------------------
# 10. Use of eval() on user input (CWE-95)
# ---------------------------------------------------------------------------
@app.route("/calc")
def calculate():
    expression = request.args.get("expr")
    result = eval(expression)  # arbitrary code execution
    return str(result)


# ---------------------------------------------------------------------------
# 11. Bonus: Insecure Temp File Creation (CWE-377)
# ---------------------------------------------------------------------------
def write_temp_file(data):
    tmp_path = "/tmp/tempfile.txt"  # predictable path, race condition risk
    with open(tmp_path, "w") as f:
        f.write(data)
    return tmp_path


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")  # debug mode + bind-all is itself a finding
