import re
import hashlib
import time
import secrets
import json
import requests

from logger import log_error

session_db = "data/sessions.json"

def check_password_strength(password):
    length = len(password)
    if length < 6:
        return "Weak", "red"
    elif length < 10:
        return "Moderate", "orange"
    elif length >= 10 and re.search(r"\d", password) and re.search(r"[A-Z]", password) and re.search(r"[a-z]", password) and re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Strong", "green"
    else:
        return "Moderate", "orange"

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_session_token():
    return secrets.token_hex(16)

def load_json(file_path):
    try:
        with open(file_path, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

def save_json(file_path, data):
    with open(file_path, "w") as file:
        json.dump(data, file, indent=4)

def load_sessions():
    return load_json(session_db)

def save_sessions(sessions):
    save_json(session_db, sessions)

def create_session(username):
    sessions = load_sessions()
    session_token = generate_session_token()
    expiry = int(time.time()) + 3600
    sessions[session_token] = {
        "username": username,
        "expiry": expiry
    }
    save_sessions(sessions)
    return session_token, expiry

def validate_session(session_token):
    sessions = load_sessions()
    if session_token in sessions:
        session = sessions[session_token]
        if session["expiry"] > int(time.time()):
            return session["username"]
    return None

def clear_session(session_token):
    sessions = load_sessions()
    if session_token in sessions:
        del sessions[session_token]
        save_sessions(sessions)

def get_active_sessions():
    sessions = load_sessions()
    active_sessions = {}
    current_time = int(time.time())
    for token, session in sessions.items():
        if session["expiry"] > current_time:
            active_sessions[token] = session
    return active_sessions

def get_ip_address():
    try:
        response = requests.get('https://api.ipify.org?format=json')
        ip = response.json().get('ip')
        return ip
    except Exception as e:
        log_error(f"Failed to get IP address. Error: {e}")
        return None

def get_geolocation(ip):
    try:
        response = requests.get(f'https://ipinfo.io/{ip}/json')
        location = response.json().get('region')
        return location
    except Exception as e:
        log_error(f"Failed to get geolocation. Error: {e}")
        return None
