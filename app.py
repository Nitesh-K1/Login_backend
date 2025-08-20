import os
import jwt
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_cors import CORS
from dotenv import load_dotenv
from database.db import create_user, check_user, check_api_key
load_dotenv()
SECRET_KEY = os.getenv("SECRET_KEY")
app = Flask(__name__)
CORS(app)
from functools import wraps

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get("x-api-key")
        if not api_key or not check_api_key(api_key):
            return jsonify({"success": False, "message": "Invalid API Key"}), 401
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"success": False, "message": "Missing JWT token"}), 401
        try:
            token = token.split(" ")[1]
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user_id = data["user_id"]
        except jwt.ExpiredSignatureError:
            return jsonify({"success": False, "message": "JWT token expired"}), 401
        except Exception:
            return jsonify({"success": False, "message": "Invalid JWT token"}), 401

        return f(*args, **kwargs)
    return decorated
# Routes
@app.route("/register", methods=["POST"])
def register():
    data = request.json
    email = data.get("email")
    password = data.get("password")
    confirm = data.get("confirm")

    if password != confirm:
        return jsonify({"success": False, "message": "Passwords do not match"}), 400

    success, message = create_user(email, password)
    if success:
        return jsonify({"success": True, "message": message})
    return jsonify({"success": False, "message": message}), 400

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    user = check_user(email, password)
    if user:
        token = jwt.encode(
            {"user_id": user["id"], "exp": datetime.utcnow() + timedelta(hours=2)},
            SECRET_KEY,
            algorithm="HS256"
        )
        return jsonify({"success": True, "token": token})
    return jsonify({"success": False, "message": "Invalid credentials"}), 401

@app.route("/profile", methods=["GET"])
@require_auth
def profile():
    return jsonify({"success": True, "user_id": request.user_id})

if __name__ == "__main__":
    app.run(debug=True)
