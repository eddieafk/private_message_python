from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from threading import Thread
import sqlite3
import os
from cryptography.fernet import Fernet
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///messages.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)

db_file = "messages.db"
encryption_key_file = "key.key"

# Generate or load encryption key
if not os.path.exists(encryption_key_file):
    key = Fernet.generate_key()
    with open(encryption_key_file, "wb") as f:
        f.write(key)
else:
    with open(encryption_key_file, "rb") as f:
        key = f.read()

cipher = Fernet(key)

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Message model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender = db.Column(db.String(80), nullable=False)
    recipient = db.Column(db.String(80), nullable=False)
    content = db.Column(db.Text, nullable=False)

# Initialize the database
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return render_template("login.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        if User.query.filter_by(username=username).first():
            return "Username already exists!"

        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login'))
    return render_template("register.html")

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('chat'))

        return "Invalid username or password!"
    return render_template("login.html")

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template("index.html", username=user.username)


@app.route('/send', methods=['POST'])
def send_message():
    if 'user_id' not in session:
        return jsonify({"status": "Unauthorized"}), 401

    data = request.get_json()
    sender = data['sender']
    recipient = data['recipient']
    content = cipher.encrypt(data['content'].encode()).decode()

    new_message = Message(sender=sender, recipient=recipient, content=content)
    db.session.add(new_message)
    db.session.commit()

    return jsonify({"status": "Message sent!"})

@app.route('/receive', methods=['POST'])
def receive_messages():
    if 'user_id' not in session:
        return jsonify({"status": "Unauthorized"}), 401

    data = request.get_json()
    recipient = data['recipient']

    messages = Message.query.filter_by(recipient=recipient).all()
    decrypted_messages = []
    for msg in messages:
        decrypted_content = cipher.decrypt(msg.content.encode()).decode()
        decrypted_messages.append({"sender": msg.sender, "content": decrypted_content})

    return jsonify(decrypted_messages)

def run_flask():
    app.run(debug=True, use_reloader=False, threaded=True)

if __name__ == "__main__":
    # Start Flask in a separate thread
    flask_thread = Thread(target=run_flask)
    flask_thread.start()