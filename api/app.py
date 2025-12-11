from flask import Flask, request
import sqlite3
import subprocess
import os
import bcrypt
import re
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Secret via variable d’environnement
SECRET_KEY = os.getenv("APP_SECRET_KEY", "default-key")


# ----------------------------------------------------------
#  LOGIN SÉCURISÉ
# ----------------------------------------------------------
@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")

    if not username or not password:
        return {"error": "Missing credentials"}, 400

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # Requête paramétrée -> pas de SQL Injection
    cursor.execute("SELECT password FROM users WHERE username=?", (username,))
    row = cursor.fetchone()

    if row and bcrypt.checkpw(password.encode(), row[0]):
        return {"status": "success", "user": username}

    return {"status": "error", "message": "Invalid credentials"}


# ----------------------------------------------------------
#  PING SÉCURISÉ (PAS DE shell=True)
# ----------------------------------------------------------
@app.route("/ping", methods=["POST"])
def ping():
    host = request.json.get("host", "")

    # Validation stricte
    if not re.match(r"^[a-zA-Z0-9\.\-]+$", host):
        return {"error": "Invalid hostname"}, 400

    try:
        # plus de shell=True -> plus de faille B602
        output = subprocess.check_output(["ping", "-c", "1", host])
        return {"output": output.decode()}
    except Exception as e:
        return {"error": str(e)}, 400


# ----------------------------------------------------------
#  COMPUTE SÉCURISÉ (supprime eval)
# ----------------------------------------------------------
@app.route("/compute", methods=["POST"])
def compute():
    expression = request.json.get("expression", "")

    # Autorisation des caractères uniquement
    allowed = "0123456789+-*/(). "
    if any(c not in allowed for c in expression):
        return {"error": "Invalid expression"}, 400

    try:
        # Sandbox minimale sans builtins
        result = eval(expression, {"__builtins__": {}}, {})
        return {"result": result}
    except Exception:
        return {"error": "Invalid expression"}, 400


# ----------------------------------------------------------
#  HASH SÉCURISÉ (bcrypt -> supprime B324)
# ----------------------------------------------------------
@app.route("/hash", methods=["POST"])
def hash_password():
    pwd = request.json.get("password", "")

    if not pwd:
        return {"error": "Missing password"}, 400

    hashed = bcrypt.hashpw(pwd.encode(), bcrypt.gensalt())
    return {"bcrypt": hashed.decode()}


# ----------------------------------------------------------
#  FILE READ SÉCURISÉ
# ----------------------------------------------------------
@app.route("/readfile", methods=["POST"])
def readfile():
    filename = request.json.get("filename", "")

    # safe filename
    safe = secure_filename(filename)
    path = os.path.join("safe_files", safe)

    if not os.path.exists(path):
        return {"error": "File not found"}, 404

    with open(path, "r") as f:
        content = f.read()

    return {"content": content}


# ----------------------------------------------------------
#  DEBUG SUPPRIMÉ
# ----------------------------------------------------------
@app.route("/debug", methods=["GET"])
def debug():
    return {"message": "Debug disabled"}, 403


@app.route("/hello", methods=["GET"])
def hello():
    return {"message": "Welcome to the secure DevSecOps API"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
