from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, jwt, datetime

app = Flask(__name__)
DATABASE = 'users.db'
SECRET_KEY = os.environ.get("SECRET_KEY", "fallback-secret")

# In-memory store (for demo purposes)
refresh_tokens = {}

def init_db():
    if not os.path.exists(DATABASE):
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute('''CREATE TABLE users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password TEXT NOT NULL
                    )''')
        conn.commit()
        conn.close()

def generate_tokens(username):
    access_payload = {
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    }
    refresh_payload = {
        'username': username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }
    access_token = jwt.encode(access_payload, SECRET_KEY, algorithm='HS256')
    refresh_token = jwt.encode(refresh_payload, SECRET_KEY, algorithm='HS256')
    refresh_tokens[username] = refresh_token
    return access_token, refresh_token

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    email = request.form.get('email')
    raw_password = request.form.get('password')
    password = generate_password_hash(raw_password)

    try:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", 
                  (username, email, password))
        conn.commit()
        conn.close()
        return jsonify({"message": "User registered successfully!"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already exists!"}), 409

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    raw_password = request.form.get('password')

    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username=?", (username,))
    result = c.fetchone()
    conn.close()

    if result and check_password_hash(result[0], raw_password):
        access_token, refresh_token = generate_tokens(username)
        return jsonify({"access_token": access_token, "refresh_token": refresh_token})
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/refresh', methods=['POST'])
def refresh():
    token = request.form.get('refresh_token')
    if not token:
        return jsonify({"error": "Refresh token missing"}), 403

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        username = decoded['username']

        if refresh_tokens.get(username) != token:
            return jsonify({"error": "Invalid refresh token"}), 401

        new_access_token, _ = generate_tokens(username)
        return jsonify({"access_token": new_access_token,
                       "refresh_token": new_refresh_token
                       })
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Refresh token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

@app.route('/protected', methods=['GET'])
def protected():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({"error": "Token is missing"}), 403
    
    if token.startswith("Bearer "):
    token = token[7:]
    
    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return jsonify({"message": f"Welcome {decoded['username']}! You accessed a protected route!"})
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Access token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

@app.route('/', methods=['GET'])
def home():
    return jsonify({"message": "Welcome to the user API!"})

if __name__ == '__main__':
    init_db()
