from flask import Flask, request, jsonify, render_template, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
import sqlite3, os, jwt, datetime, random, time
from google.oauth2 import id_token
from google.auth.transport import requests as grequests

# === CONFIGURATION ===
app = Flask(__name__)
SECRET_KEY = os.environ.get("SECRET_KEY", "fallback-secret")
app.secret_key = SECRET_KEY
DATABASE = 'users.db'
refresh_tokens = {}

# Email config - replace with your credentials
app.config.update({
    'MAIL_SERVER': 'smtp.gmail.com',
    'MAIL_PORT': 587,
    'MAIL_USE_TLS': True,
    'MAIL_USERNAME': 'your@email.com',
    'MAIL_PASSWORD': 'your_app_password'
})
mail = Mail(app)

# Load disposable email domains
with open('disposable_domains.txt') as f:
    DISPOSABLE_DOMAINS = set(map(str.strip, f))

def is_disposable_email(email):
    return email.split('@')[1].lower() in DISPOSABLE_DOMAINS

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS otp (
            email TEXT PRIMARY KEY,
            code TEXT NOT NULL,
            timestamp INTEGER NOT NULL
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

@app.route('/')
def home():
    return render_template("auth.html")

@app.route('/send-otp', methods=['POST'])
def send_otp():
    email = request.json.get('email')
    if is_disposable_email(email):
        return jsonify({'error': 'Temporary email not allowed'}), 400

    otp = str(random.randint(100000, 999999))
    conn = sqlite3.connect(DATABASE)
    conn.execute("REPLACE INTO otp (email, code, timestamp) VALUES (?, ?, ?)",
                 (email, otp, int(time.time())))
    conn.commit()
    conn.close()

    msg = Message("Your OTP Code", sender=app.config['MAIL_USERNAME'], recipients=[email])
    msg.body = f"Your OTP is: {otp}"
    mail.send(msg)
    return jsonify({'message': 'OTP sent'})

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    email = request.json.get('email')
    code = request.json.get('otp')
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    cur.execute("SELECT code, timestamp FROM otp WHERE email=?", (email,))
    row = cur.fetchone()
    conn.close()

    if row and row[0] == code and time.time() - row[1] < 300:
        return jsonify({'verified': True})
    return jsonify({'verified': False}), 400

@app.route('/google-login', methods=['POST'])
def google_login():
    token = request.json.get('id_token')
    try:
        idinfo = id_token.verify_oauth2_token(token, grequests.Request(), "YOUR_GOOGLE_CLIENT_ID")
        email = idinfo['email']
        username = idinfo.get('name', email.split('@')[0])

        if is_disposable_email(email):
            return jsonify({"error": "Disposable emails are not allowed"}), 400

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email=?", (email,))
        if not c.fetchone():
            c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                      (username, email, generate_password_hash(os.urandom(8).hex())))
            conn.commit()
        conn.close()

        access_token, refresh_token = generate_tokens(username)
        resp = jsonify({"access_token": access_token})
        resp.set_cookie('refresh_token', refresh_token, httponly=True, samesite='Strict')
        return resp

    except ValueError:
        return jsonify({"error": "Invalid Google token"}), 400

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
        response.set_cookie('refresh_token', new_refresh_token, httponly=True, samesite='Strict')
        return response
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Refresh token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

@app.route('/logout', methods=['POST'])
def logout():
    token = request.cookies.get('refresh_token')
    if token:
        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            refresh_tokens.pop(decoded['username'], None)
        except:
            pass
    resp = jsonify({'message': 'Logged out'})
    resp.set_cookie('refresh_token', '', expires=0)
    return resp

@app.route('/protected', methods=['GET'])
def protected():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({"error": "Token is missing"}), 403
    try:
        token = auth_header.split()[1]
        decoded = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        return jsonify({"message": f"Welcome {decoded['username']}!"})
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Access token expired"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 401

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
