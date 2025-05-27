from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, os, jwt, datetime

app = Flask(__name__)
SECRET_KEY = os.environ.get("SECRET_KEY", "fallback-secret")
app.secret_key = SECRET_KEY
DATABASE = 'users.db'
refresh_tokens = {}

def init_db():
    if not os.path.exists(DATABASE):
        with sqlite3.connect(DATABASE) as conn:
            conn.execute('''CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )''')
            conn.commit()

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
        conn.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                     (username, email, password))
        conn.commit()
        conn.close()

        access_token, refresh_token = generate_tokens(username)
        response = jsonify({"message": "Registration successful!", "access_token": access_token})
        response.set_cookie('refresh_token', refresh_token, httponly=True, secure=True, samesite='Strict')
        return response

    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already exists!"}), 409

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    raw_password = request.form.get('password')

    conn = sqlite3.connect(DATABASE)
    cursor = conn.execute("SELECT password FROM users WHERE username=?", (username,))
    result = cursor.fetchone()
    conn.close()

    if result and check_password_hash(result[0], raw_password):
        access_token, refresh_token = generate_tokens(username)
        response = jsonify({"access_token": access_token})
        response.set_cookie('refresh_token', refresh_token, httponly=True, secure=True, samesite='Strict')
        return response
    return jsonify({"error": "Invalid credentials"}), 401

@app.route('/refresh', methods=['POST'])
def refresh():
    token = request.cookies.get('refresh_token')
    if not token:
        return jsonify({"error": "Refresh token missing"}), 403

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        username = decoded['username']

        if refresh_tokens.get(username) != token:
            return jsonify({"error": "Invalid refresh token"}), 401

        new_access_token, new_refresh_token = generate_tokens(username)
        response = jsonify({"access_token": new_access_token})
        response.set_cookie('refresh_token', new_refresh_token, httponly=True, secure=True, samesite='Strict')
        return response

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Refresh token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

@app.route('/protected', methods=['GET'])
def protected():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"error": "Token is missing"}), 403

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return jsonify({"error": "Invalid token header"}), 401

    try:
        decoded = jwt.decode(parts[1], SECRET_KEY, algorithms=['HS256'])
        return jsonify({"message": f"Welcome {decoded['username']}! You accessed a protected route!"})
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Access token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

@app.route('/logout', methods=['POST'])
def logout():
    refresh_token = request.cookies.get('refresh_token')
    if refresh_token:
        try:
            decoded = jwt.decode(refresh_token, SECRET_KEY, algorithms=['HS256'])
            username = decoded['username']
            refresh_tokens.pop(username, None)
        except jwt.InvalidTokenError:
            pass

    response = jsonify({"message": "Logged out successfully"})
    response.set_cookie('refresh_token', '', expires=0, httponly=True, secure=True, samesite='Strict')
    return response

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/auth')
def auth():
    return render_template("auth.html")
    
@app.route('/dashboard')
def dashboard():
    return render_template("dashboard.html")

@app.route('/health')
def health():
    return "OK", 200

if __name__ == '__main__':
    init_db()
    app.run()
