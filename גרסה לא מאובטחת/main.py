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

EMAIL_ADDRESS = config['email_user']
EMAIL_PASSWORD = config['email_pass']

conn_str = (
    r"DRIVER={ODBC Driver 17 for SQL Server};"
    r"SERVER=(LocalDB)\MSSQLLocalDB;"
    r"DATABASE=Communication_LTD;"
    r"Trusted_Connection=yes;"
)
conn = pyodbc.connect(conn_str)
cursor = conn.cursor()

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
    except Exception as e:
        print(f"Email failed to send: {e}")

def password_valid(password):
    rules = config['password_rules']
    return (len(password) >= rules['min_length'] and
            any(c.isupper() for c in password) and
            any(c.islower() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in rules['special_chars'] for c in password))

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

        # ❌ SQL Injection vulnerable
        query = f"SELECT 1 FROM users WHERE username='{username}' OR email='{email}'"
        cursor.execute(query)
        if cursor.fetchone():
            flash("Username or email already exists")
            return redirect(url_for('register'))

        salt = generate_salt()
        hashed = hash_password(password, salt)
        # ❌ SQL Injection vulnerable
        insert_query = f"INSERT INTO users (username, email, salt, password) VALUES ('{username}', '{email}', '{salt}', '{hashed}')"
        cursor.execute(insert_query)
        conn.commit()
        flash("Registered successfully. Please login.")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # 💀 SQL Injection vulnerability with full bypass
        query = f"SELECT username FROM users WHERE username='{username}' AND password='{password}'"
        print(f"Running query: {query}")  # For debugging
        cursor.execute(query)
        row = cursor.fetchone()
        if row:
            session['username'] = row.username
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

    # ❌ Stored XSS vulnerable
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
        # ❌ Stored XSS vulnerable
        query = f"INSERT INTO clients (name) OUTPUT INSERTED.id VALUES ('{name}')"
        cursor.execute(query)
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

        # ❌ SQL Injection vulnerable
        query = f"SELECT salt, password FROM users WHERE username='{username}'"
        cursor.execute(query)
        row = cursor.fetchone()
        if row and hash_password(current, row.salt) == row.password:
            if not password_valid(new_pass):
                flash("New password does not meet requirements")
                return redirect(url_for('change_password'))
            new_salt = generate_salt()
            new_hash = hash_password(new_pass, new_salt)
            update_query = f"UPDATE users SET salt='{new_salt}', password='{new_hash}' WHERE username='{username}'"
            cursor.execute(update_query)
            conn.commit()
            flash("Password changed successfully")
        else:
            flash("Current password incorrect")
    return render_template('change_password.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        # ❌ SQL Injection vulnerable
        query = f"SELECT username FROM users WHERE email='{email}'"
        cursor.execute(query)
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
        # ❌ SQL Injection vulnerable
        cursor.execute(f"SELECT username FROM users WHERE email='{email}'")
        user = cursor.fetchone()
        if user:
            if not password_valid(new_pass):
                flash("New password does not meet requirements")
                return redirect(url_for('reset_password'))
            salt = generate_salt()
            hashed = hash_password(new_pass, salt)
            update_query = f"UPDATE users SET salt='{salt}', password='{hashed}' WHERE email='{email}'"
            cursor.execute(update_query)
            conn.commit()
            flash("Password reset successful")
            return redirect(url_for('login'))
        else:
            flash("User not found")
            return redirect(url_for('forgot_password'))
    return render_template('reset_password.html')

if __name__ == '__main__':
    app.run(debug=True)
