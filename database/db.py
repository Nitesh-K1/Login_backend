import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
db = mysql.connector.connect(
    host="localhost",
    user="root",
    password="Admin@123",
    database="login_form"
)
cursor = db.cursor(dictionary=True)
def check_user(email: str, password: str):
    query = "SELECT * FROM users WHERE email=%s"
    cursor.execute(query, (email,))
    user = cursor.fetchone()
    if user and check_password_hash(user["password"], password):
        return user
    return None
def check_api_key(api_key: str):
    cursor.execute("SELECT * FROM api_keys WHERE key=%s", (api_key,))
    return cursor.fetchone() is not None
def create_user(email: str, password: str):
    cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
    if cursor.fetchone():
        return False, "Email already registered"

    hashed = generate_password_hash(password)
    cursor.execute(
        "INSERT INTO users (email, password) VALUES (%s, %s)", (email, hashed)
    )
    db.commit()
    return True, "User created successfully"
