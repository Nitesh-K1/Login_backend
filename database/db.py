import mysql.connector
from mysql.connector import Error
from dotenv import load_dotenv
import os
from werkzeug.security import generate_password_hash, check_password_hash
load_dotenv()
MYSQL_CONFIG = {
    "host": os.getenv("MYSQL_HOST"),
    "user": os.getenv("MYSQL_USER"),
    "password": os.getenv("MYSQL_PASS"),
    "database": os.getenv("MYSQL_DB")
}

def get_db_connection():
    return mysql.connector.connect(**MYSQL_CONFIG)

def check_user(email: str, password: str):
    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        query = "SELECT * FROM users WHERE email=%s"
        cursor.execute(query, (email,))
        user = cursor.fetchone()
        cursor.close()
        db.close()
        if user and check_password_hash(user["password"], password):
            return user
        return None
    except Error as e:
        print("Error checking user:", e)
        return None

def check_api_key(api_key: str):
    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM api_keys WHERE key=%s", (api_key,))
        result = cursor.fetchone() is not None
        cursor.close()
        db.close()
        return result
    except Error as e:
        print("Error checking API key:", e)
        return False

def create_user(email: str, password: str):
    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        if cursor.fetchone():
            cursor.close()
            db.close()
            return False, "Email already registered"
        hashed = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (email, password) VALUES (%s, %s)", (email, hashed)
        )
        db.commit()
        cursor.close()
        db.close()
        return True, "User created successfully"
    except Error as e:
        print("Error creating user:", e)
        return False, str(e)
