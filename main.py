from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import jwt
import datetime

app = Flask(__name__)
SECRET_KEY = os.environ.get("SECRET_KEY", "fallback-secret")
app.secret_key = SECRET_KEY
DATABASE = 'users.db'

# In-memory store (for demo purposes)
refresh_tokens = {}

def init_db():
    if not os.path.exists(DATABASE):
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE users (
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
        c = conn.cursor()
        c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)", 
                  (username, email, password))
        conn.commit()
        conn.close()

        # Auto-login after registration
        access_token, refresh_token = generate_tokens(username)

        response = jsonify({
            "message": "Registration successful!",
            "access_token": access_token
        })
        response.set_cookie(
            'refresh_token',
            refresh_token,
            httponly=True,
            secure=True,        # Use HTTPS
            samesite='Strict'
        )
        return response

    except sqlite3.IntegrityError:
        return jsonify({"error": "Username or email already exists!"}), 409

@app.route('/login', methods=['GET'])
def login_page():
    return render_template("login.html")
    
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
        # Generate tokens
        access_token, refresh_token = generate_tokens(username)

        # Set refresh token in secure, HTTP-only cookie
        response = jsonify({
            "access_token": access_token
        })
        response.set_cookie(
            'refresh_token',
            refresh_token,
            httponly=True,
            secure=True,        # Important: use HTTPS in production
            samesite='Strict'   # Adjust if needed
        )
        return response
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/refresh', methods=['POST'])
def refresh():
    # Get refresh token from HTTP-only cookie
    token = request.cookies.get('refresh_token')
    if not token:
        return jsonify({"error": "Refresh token missing"}), 403

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        username = decoded['username']

        # Check if token matches the one stored
        if refresh_tokens.get(username) != token:
            return jsonify({"error": "Invalid refresh token"}), 401

        # Generate new tokens
        new_access_token, new_refresh_token = generate_tokens(username)

        # Set new refresh token in HTTP-only cookie
        response = jsonify({
            "access_token": new_access_token
        })
        response.set_cookie(
            'refresh_token',
            new_refresh_token,
            httponly=True,
            secure=True,        # Make sure you use HTTPS in production
            samesite='Strict'   # Adjust as needed: 'Lax', 'None', or 'Strict'
        )
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

    # Expecting header like: "Bearer <token>"
    parts = auth_header.split()

    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return jsonify({"error": "Invalid token header"}), 401

    token = parts[1]

    try:
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return jsonify({"message": f"Welcome {decoded['username']}! You accessed a protected route!"})
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Access token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

@app.route('/logout', methods=['POST'])
def logout():
    response = jsonify({"message": "Logged out successfully"})

    # Remove refresh token from in-memory store
    refresh_token = request.cookies.get('refresh_token')
    if refresh_token:
        try:
            decoded = jwt.decode(refresh_token, SECRET_KEY, algorithms=['HS256'])
            username = decoded['username']
            refresh_tokens.pop(username, None)
        except jwt.InvalidTokenError:
            pass

    # Clear the cookie
    response.set_cookie(
        'refresh_token',
        '',
        expires=0,
        httponly=True,
        secure=True,
        samesite='Strict'
    )
    return response

@app.route('/', methods=['GET'])
def home():
    return render_template("index.html")

if __name__ == '__main__':
    init_db()
