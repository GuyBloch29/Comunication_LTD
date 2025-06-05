import os
import json
import hashlib
import hmac
import random
import string
import smtplib
from email.message import EmailMessage
from flask import Flask, request, render_template, session, redirect, url_for, flash
import pyodbc

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Load config
with open('config.json') as f:
    config = json.load(f)

# Email config (put this in config.json ideally)
EMAIL_ADDRESS = config['email_user']
EMAIL_PASSWORD = config['email_pass']

# Database connection
conn_str = (
    r"DRIVER={ODBC Driver 17 for SQL Server};"
    r"SERVER=(LocalDB)\MSSQLLocalDB;"
    r"DATABASE=Communication_LTD;"
    r"Trusted_Connection=yes;"
)
conn = pyodbc.connect(conn_str)
cursor = conn.cursor()

# Utils
def hash_password(password, salt):
    return hmac.new(salt.encode(), password.encode(), hashlib.sha256).hexdigest()

def generate_salt():
    return os.urandom(16).hex()

def generate_token():
    rand_val = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
    return hashlib.sha1(rand_val.encode()).hexdigest()

def send_email(to_email, token):
    msg = EmailMessage()
    msg['Subject'] = 'Your Password Reset Token'
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = to_email
    msg.set_content(f'Here is your password reset token: {token}')

    try:
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        print(f"Email sent to {to_email}")
    except Exception as e:
        print(f"Email failed to send: {e}")

def password_valid(password):
    rules = config['password_rules']
    if len(password) < rules['min_length']:
        return False
    if not any(c.isupper() for c in password):
        return False
    if not any(c.islower() for c in password):
        return False
    if not any(c.isdigit() for c in password):
        return False
    if not any(c in rules['special_chars'] for c in password):
        return False
    return True

# Routes

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']

        if not password_valid(password):
            flash("Password does not meet requirements")
            return redirect(url_for('register'))

        cursor.execute("SELECT 1 FROM users WHERE username=? OR email=?", username, email)
        if cursor.fetchone():
            flash("Username or email already exists")
            return redirect(url_for('register'))

        salt = generate_salt()
        hashed = hash_password(password, salt)
        cursor.execute("INSERT INTO users (username, email, salt, password) VALUES (?, ?, ?, ?)",
                       username, email, salt, hashed)
        conn.commit()
        flash("Registered successfully. Please login.")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cursor.execute("SELECT salt, password FROM users WHERE username=?", username)
        row = cursor.fetchone()
        if row and hash_password(password, row.salt) == row.password:
            session['username'] = username
            flash("Login successful")
            return redirect(url_for('dashboard'))
        else:
            flash("Login failed: invalid username or password")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully")
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        flash("Please login first")
        return redirect(url_for('login'))
    cursor.execute("SELECT id, name FROM clients")
    clients = cursor.fetchall()
    return render_template('dashboard.html', username=session['username'], clients=clients)

@app.route('/new_client', methods=['GET', 'POST'])
def new_client():
    if 'username' not in session:
        flash("Please login first")
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form['name']
        cursor.execute("INSERT INTO clients (name) OUTPUT INSERTED.id VALUES (?)", name)
        new_id = cursor.fetchone()[0]
        conn.commit()
        flash(f"Added client: {name} (ID: {new_id})")
        return redirect(url_for('dashboard'))
    return render_template('new_client.html')

@app.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'username' not in session:
        flash("Please login first")
        return redirect(url_for('login'))

    if request.method == 'POST':
        current = request.form['current']
        new_pass = request.form['new']
        username = session['username']
        cursor.execute("SELECT salt, password FROM users WHERE username=?", username)
        row = cursor.fetchone()
        if row and hash_password(current, row.salt) == row.password:
            if not password_valid(new_pass):
                flash("New password does not meet requirements")
                return redirect(url_for('change_password'))
            new_salt = generate_salt()
            new_hash = hash_password(new_pass, new_salt)
            cursor.execute("UPDATE users SET salt=?, password=? WHERE username=?", new_salt, new_hash, username)
            conn.commit()
            flash("Password changed successfully")
        else:
            flash("Current password incorrect")
    return render_template('change_password.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        cursor.execute("SELECT username FROM users WHERE email=?", email)
        user = cursor.fetchone()
        if not user:
            flash("Email not found")
            return redirect(url_for('forgot_password'))

        token = generate_token()
        session['reset_token'] = token
        session['reset_email'] = email
        send_email(email, token)
        flash("Token sent to your email")
        return redirect(url_for('verify_token'))
    return render_template('forgot_password.html')

@app.route('/verify_token', methods=['GET', 'POST'])
def verify_token():
    if request.method == 'POST':
        token = request.form['token']
        if token == session.get('reset_token'):
            flash("Token verified. Please reset your password.")
            return redirect(url_for('reset_password'))
        else:
            flash("Invalid token")
    return render_template('verify_token.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        new_pass = request.form['new']
        email = session.get('reset_email')
        cursor.execute("SELECT username FROM users WHERE email=?", email)
        user = cursor.fetchone()
        if user:
            if not password_valid(new_pass):
                flash("New password does not meet requirements")
                return redirect(url_for('reset_password'))
            salt = generate_salt()
            hashed = hash_password(new_pass, salt)
            cursor.execute("UPDATE users SET salt=?, password=? WHERE email=?", salt, hashed, email)
            conn.commit()
            flash("Password reset successful")
            return redirect(url_for('login'))
        else:
            flash("User not found")
            return redirect(url_for('forgot_password'))
    return render_template('reset_password.html')

if __name__ == '__main__':
    app.run(debug=True)
