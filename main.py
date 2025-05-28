from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import sqlite3
import os
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

# Configuration
app.secret_key = os.getenv("FLASK_SECRET_KEY", "fallback_secret")
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "fallback_jwt_secret")
DATABASE = 'users.db'


# ====== DB SETUP ======
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
            c.execute('''CREATE TABLE refresh_tokens (
                            username TEXT PRIMARY KEY,
                            token TEXT NOT NULL
                        )''')
            conn.commit()

init_db()


# ====== TOKEN HELPERS ======
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
    store_refresh_token(username, refresh_token)
    return access_token, refresh_token

def store_refresh_token(username, token):
    with sqlite3.connect(DATABASE) as conn:
        conn.execute("REPLACE INTO refresh_tokens (username, token) VALUES (?, ?)", (username, token))
        conn.commit()

def get_stored_refresh_token(username):
    with sqlite3.connect(DATABASE) as conn:
        result = conn.execute("SELECT token FROM refresh_tokens WHERE username=?", (username,)).fetchone()
        return result[0] if result else None

def remove_refresh_token(username):
    with sqlite3.connect(DATABASE) as conn:
        conn.execute("DELETE FROM refresh_tokens WHERE username=?", (username,))
        conn.commit()


# ====== ROUTES ======
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/auth')
def auth():
    return render_template('auth.html')

@app.route('/dashboard.html')
def dashboard():
    return render_template('dashboard.html')


# ====== REGISTER ======
@app.route('/register', methods=['POST'])
def register():
    data = request.form
    username = data.get('username')
    email = data.get('email')
    password = generate_password_hash(data.get('password'))

    with sqlite3.connect(DATABASE) as conn:
        try:
            conn.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                         (username, email, password))
            conn.commit()
        except sqlite3.IntegrityError:
            return jsonify({'error': 'Username or email already exists.'}), 400

    access_token, refresh_token = generate_tokens(username)
    flash('Registered successfully!', 'success')
    return jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200


# ====== LOGIN ======
@app.route('/login', methods=['POST'])
def login():
    data = request.form
    username = data.get('username')
    password = data.get('password')

    with sqlite3.connect(DATABASE) as conn:
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        if not user or not check_password_hash(user[3], password):
            return jsonify({'error': 'Invalid username or password'}), 401

    access_token, refresh_token = generate_tokens(username)
    flash('Logged in successfully!', 'success')
    return jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200


# ====== REFRESH TOKEN ======
@app.route('/refresh', methods=['POST'])
def refresh():
    token = request.form.get('refresh_token')
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        username = payload['username']
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Refresh token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid refresh token'}), 401

    if get_stored_refresh_token(username) != token:
        return jsonify({'error': 'Refresh token mismatch'}), 401

    access_token, new_refresh_token = generate_tokens(username)
    return jsonify({'access_token': access_token, 'refresh_token': new_refresh_token}), 200


# ====== LOGOUT ======
@app.route('/logout', methods=['POST'])
def logout():
    token = request.form.get('refresh_token')
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        remove_refresh_token(payload['username'])
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid refresh token'}), 401

    return jsonify({'message': 'Logged out'}), 200


# ====== PROTECTED TEST ROUTE (OPTIONAL) ======
@app.route('/protected')
def protected():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'error': 'Token missing'}), 403
    token = auth_header.split()[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Access token expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid access token'}), 401
    return jsonify({'message': f'Welcome {payload["username"]}'}), 200


if __name__ == '__main__':
    app.run(debug=False)
