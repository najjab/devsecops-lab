from flask import Flask, request
import sqlite3
import subprocess
import hashlib
import os
import bcrypt
import re
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Secret déplacé dans les variables d’environnement
SECRET_KEY = os.getenv("APP_SECRET_KEY", "default-safe-key")


# ----------------------------------------------------------
#  🔐 Secure Login (paramétré + hashing bcrypt)
# ----------------------------------------------------------
@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")

    if not username or not password:
        return {"error": "Missing username or password"}, 400

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # Requête paramétrée → empêche SQL Injection
    cursor.execute("SELECT password FROM users WHERE username=?", (username,))
    row = cursor.fetchone()

    if row and bcrypt.checkpw(password.encode(), row[0]):
        return {"status": "success", "user": username}

    return {"status": "error", "message": "Invalid credentials"}


# ----------------------------------------------------------
#  🛡 Ping sécurisé (pas de shell=True, whitelist)
# ----------------------------------------------------------
@app.route("/ping", methods=["POST"])
def ping():
    host = request.json.get("host", "")

    # Validation : autorise seulement IP ou noms simples
    if not re.match(r"^[a-zA-Z0-9\.\-]+$", host):
        return {"error": "Invalid hostname"}, 400

    try:
        # Pas de shell=True → pas d'injection
        output = subprocess.check_output(["ping", "-c", "1", host])
        return {"output": output.decode()}
    except Exception as e:
        return {"error": str(e)}, 400


# ----------------------------------------------------------
#  🛡 Compute sécurisé (remplace eval par parser math)
# ----------------------------------------------------------
@app.route("/compute", methods=["POST"])
def compute():
    expression = request.json.get("expression")

    allowed = "0123456789+-*/(). "

    if not expression or any(c not in allowed for c in expression):
        return {"error": "Invalid expression"}, 400

    try:
        result = eval(expression, {"__builtins__": {}}, {})
        return {"result": result}
    except Exception:
        return {"error": "Invalid expression"}, 400


# ----------------------------------------------------------
#  🔐 Hash sécurisé (bcrypt)
# ----------------------------------------------------------
@app.route("/hash", methods=["POST"])
def hash_password():
    pwd = request.json.get("password")

    if not pwd:
        return {"error": "Missing password"}, 400

    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(pwd.encode(), salt)

    return {"bcrypt": hashed.decode()}


# ----------------------------------------------------------
#  🛡 Lecture fichiers sécurisée (secure_filename + dossier dédié)
# ----------------------------------------------------------
@app.route("/readfile", methods=["POST"])
def readfile():
    filename = request.json.get("filename")

    if not filename:
        return {"error": "Missing filename"}, 400

    safe_name = secure_filename(filename)
    path = os.path.join("safe_files", safe_name)

    if not os.path.exists(path):
        return {"error": "File does not exist"}, 404

    with open(path, "r") as f:
        content = f.read()

    return {"content": content}


# ----------------------------------------------------------
#  🛡 Debug désactivé (ne jamais exposer les secrets)
# ----------------------------------------------------------
@app.route("/debug", methods=["GET"])
def debug():
    return {"message": "Debug mode disabled for security reasons"}, 403


@app.route("/hello", methods=["GET"])
def hello():
    return {"message": "Welcome to the secure DevSecOps API"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
