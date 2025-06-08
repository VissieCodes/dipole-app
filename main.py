from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, make_response, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import sqlite3, os, jwt, datetime, random, string
from functools import wraps
from google.oauth2 import id_token
from google.auth.transport import requests as grequests

app = Flask(__name__)
SECRET_KEY = os.environ.get("SECRET_KEY", "fallback-secret")
app.secret_key = SECRET_KEY
DATABASE = 'users.db'
refresh_tokens = {}
OTP_STORE = {}

# Flask-Mail configuration
app.config.update({
    'MAIL_SERVER': 'smtp.gmail.com',
    'MAIL_PORT': 587,
    'MAIL_USE_TLS': True,
    'MAIL_USERNAME': 'your@email.com',  # change this
    'MAIL_PASSWORD': 'your_app_password'  # change this
})
mail = Mail(app)

# Load disposable domains
with open("disposable_domains.txt") as f:
    DISPOSABLE_DOMAINS = set(line.strip().lower() for line in f if line.strip())

def init_db():
    if not os.path.exists(DATABASE):
        with sqlite3.connect(DATABASE) as conn:
            conn.execute('''CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT,
                is_verified INTEGER DEFAULT 0,
                is_admin INTEGER DEFAULT 0
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

def send_otp(email):
    otp = ''.join(random.choices(string.digits, k=6))
    OTP_STORE[email] = otp
    msg = Message('Your OTP Code', recipients=[email], body=f"Your OTP is: {otp}")
    mail.send(msg)

def email_is_disposable(email):
    domain = email.split('@')[-1].lower()
    return domain in DISPOSABLE_DOMAINS

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/auth')
def auth_page():
    return render_template('auth.html')

@app.route('/send-otp', methods=['POST'])
def send_otp_route():
    email = request.form.get('email')
    if email_is_disposable(email):
        return jsonify({"error": "Disposable emails are not allowed."}), 400
    send_otp(email)
    return jsonify({"message": "OTP sent!"})

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    email = request.form.get('email')
    raw_password = request.form.get('password')
    otp = request.form.get('otp')

    if not username or not email or not raw_password or not otp:
        return jsonify({'error': 'Missing fields'}), 400

    if OTP_STORE.get(email) != otp:
        return jsonify({'error': 'Invalid OTP'}), 400

    if email_is_disposable(email):
        return jsonify({'error': 'Disposable email not allowed'}), 400

    password = generate_password_hash(raw_password)

    try:
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        is_admin = 1 if email == 'admin@yourdomain.com' else 0
        c.execute("INSERT INTO users (username, email, password, is_verified, is_admin) VALUES (?, ?, ?, 1, ?)", 
                  (username, email, password, is_admin))
        conn.commit()
        conn.close()

        access_token, refresh_token = generate_tokens(username)
        response = jsonify({"message": "Registration successful!", "access_token": access_token})
        response.set_cookie('refresh_token', refresh_token, httponly=True, secure=False, samesite='Strict')
        return response

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
        response = jsonify({"message": "Login successful", "access_token": access_token})
        response.set_cookie('refresh_token', refresh_token, httponly=True, secure=False, samesite='Strict')
        return response
    else:
        return jsonify({"error": "Invalid credentials"}), 401

@app.route('/google-login', methods=['POST'])
def google_login():
    token = request.json.get('credential')
    try:
        idinfo = id_token.verify_oauth2_token(token, grequests.Request())
        email = idinfo['email']
        username = idinfo.get('name') or email.split('@')[0]

        if email_is_disposable(email):
            return jsonify({'error': 'Disposable email not allowed'}), 400

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE email=?", (email,))
        user = c.fetchone()
        if not user:
            c.execute("INSERT INTO users (username, email, password, is_verified) VALUES (?, ?, '', 1)", (username, email))
            conn.commit()
        conn.close()

        access_token, refresh_token = generate_tokens(username)
        response = jsonify({"message": "Google login successful", "access_token": access_token})
        response.set_cookie('refresh_token', refresh_token, httponly=True, secure=False, samesite='Strict')
        return response

    except Exception as e:
        return jsonify({'error': 'Invalid Google token'}), 400

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

@app.route('/protected')
def protected():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"error": "Token is missing"}), 403

    parts = auth_header.split()
    if len(parts) != 2 or parts[0].lower() != 'bearer':
        return jsonify({"error": "Invalid token header"}), 401

    try:
        decoded = jwt.decode(parts[1], SECRET_KEY, algorithms=['HS256'])
        return jsonify({"message": f"Welcome {decoded['username']}!"})
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

@app.route('/dashboard')
def dashboard():
    dummy_users = [
        {"name": "John", "age": 28, "distance": "2 miles"},
        {"name": "Alex", "age": 30, "distance": "1 mile"},
        {"name": "Mark", "age": 24, "distance": "3 miles"},
        {"name": "Chris", "age": 29, "distance": "0.5 mile"},
    ]
    return render_template("dashboard.html", users=dummy_users)

@app.route('/health')
def health():
    return "OK", 200

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
