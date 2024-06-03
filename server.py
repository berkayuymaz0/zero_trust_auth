import logging
from flask import Flask, request, jsonify, session
import hashlib
import os
import re
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.secret_key = os.urandom(24)  # Use a secure random key for session

# Configure logging
logging.basicConfig(filename='app.log', level=logging.INFO, format='%(asctime)s %(message)s')

# Configure rate limiting
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user_db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

# Ensure database tables are created
with app.app_context():
    db.create_all()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def authenticate(username, password):
    user = User.query.filter_by(username=username).first()
    if user and user.password == hash_password(password):
        return True
    return False

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, ""

@app.route('/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    user_ip = request.remote_addr

    if authenticate(username, password):
        session['username'] = username
        logging.info(f"Login successful for user: {username} from IP: {user_ip}")
        return jsonify({'message': f'Welcome {username}', 'username': username}), 200
    else:
        logging.warning(f"Failed login attempt for user: {username} from IP: {user_ip}")
        return jsonify({'message': 'Incorrect username or password'}), 401

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    new_user = data.get('username')
    new_password = data.get('password')

    valid, message = validate_password(new_password)
    if not valid:
        return jsonify({'message': message}), 400

    if User.query.filter_by(username=new_user).first():
        logging.warning(f"Signup attempt with existing username: {new_user}")
        return jsonify({'message': 'User already exists'}), 409
    else:
        hashed_password = hash_password(new_password)
        new_user = User(username=new_user, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        logging.info(f"New user created: {new_user.username}")
        return jsonify({'message': 'Account created successfully'}), 201

@app.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.json
    username = data.get('username')
    new_password = data.get('new_password')

    valid, message = validate_password(new_password)
    if not valid:
        return jsonify({'message': message}), 400

    user = User.query.filter_by(username=username).first()
    if user:
        user.password = hash_password(new_password)
        db.session.commit()
        logging.info(f"Password reset for user: {username}")
        return jsonify({'message': 'Password reset successfully'}), 200
    else:
        logging.warning(f"Password reset attempt for non-existing user: {username}")
        return jsonify({'message': 'User not found'}), 404

@app.route('/update_profile', methods=['POST'])
def update_profile():
    data = request.json
    username = session.get('username')
    new_password = data.get('new_password')

    if not username:
        return jsonify({'message': 'Unauthorized'}), 401

    valid, message = validate_password(new_password)
    if not valid:
        return jsonify({'message': message}), 400

    user = User.query.filter_by(username=username).first()
    if user:
        user.password = hash_password(new_password)
        db.session.commit()
        logging.info(f"Profile updated for user: {username}")
        return jsonify({'message': 'Profile updated successfully'}), 200
    else:
        logging.warning(f"Profile update attempt for non-existing user: {username}")
        return jsonify({'message': 'User not found'}), 404

@app.route('/logout', methods=['POST'])
def logout():
    session.pop('username', None)
    return jsonify({'message': 'Logged out successfully'}), 200

@app.route('/logs', methods=['GET'])
def get_logs():
    with open('app.log', 'r') as log_file:
        logs = log_file.readlines()
    return jsonify({'logs': logs}), 200

@app.errorhandler(400)
def bad_request(error):
    return jsonify({'message': 'Bad Request'}), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'message': 'Unauthorized'}), 401

@app.errorhandler(404)
def not_found(error):
    return jsonify({'message': 'Not Found'}), 404

@app.errorhandler(500)
def internal_server_error(error):
    logging.error(f"Server Error: {error}, route: {request.url}")
    return jsonify({'message': 'Internal Server Error'}), 500

if __name__ == '__main__':
    app.run(debug=True)
