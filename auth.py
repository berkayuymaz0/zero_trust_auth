import json
import bcrypt
import secrets
import time
import smtplib
from email.mime.text import MIMEText
from activity_log import log_activity
from logger import log_info, log_error
from utils import load_json, save_json, generate_session_token, get_ip_address, get_geolocation

# File paths
users_db = "data/users.json"
devices_db = "data/devices.json"
whitelisted_ips_db = "data/whitelisted_ips.json"
blocked_geo_db = "data/blocked_geo.json"

def load_users():
    return load_json(users_db)

def save_users(users):
    save_json(users_db, users)

def load_devices():
    return load_json(devices_db)

def save_devices(devices):
    save_json(devices_db, devices)

def load_whitelisted_ips():
    return load_json(whitelisted_ips_db)

def save_whitelisted_ips(ips):
    save_json(whitelisted_ips_db, ips)

def load_blocked_geo():
    return load_json(blocked_geo_db)

def save_blocked_geo(locations):
    save_json(blocked_geo_db, locations)

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode(), stored_password.encode())

def send_otp_email(username, otp):
    users = load_users()
    if username in users:
        user_email = users[username].get("email")
        if user_email:
            msg = MIMEText(f"Your OTP is: {otp}")
            msg['Subject'] = 'Your OTP Code'
            msg['From'] = 'noreply@secureapp.com'
            msg['To'] = user_email

            smtp_server = 'sandbox.smtp.mailtrap.io'
            smtp_port = 587
            smtp_user = '70754b8ca579ec'
            smtp_password = 'b0bfc9639ae21c'

            try:
                with smtplib.SMTP(smtp_server, smtp_port) as server:
                    server.starttls()
                    server.login(smtp_user, smtp_password)
                    server.send_message(msg)
                return True
            except Exception as e:
                log_error(f"Failed to send OTP email to {username}. Error: {e}")
                return False
    return False

def generate_otp():
    return secrets.token_hex(4)

def get_time_remaining():
    return 30 - (int(time.time()) % 30)

def verify_otp(username, otp_input):
    users = load_users()
    if username in users:
        stored_otp = users[username].get('otp')
        if stored_otp and stored_otp == otp_input:
            users[username]['otp'] = None
            save_users(users)
            return True
    return False

def login(username, password):
    users = load_users()
    if username in users:
        if check_password(users[username]["password"], password):
            log_activity(username, "login")
            return True
        else:
            log_error(f"Password mismatch for user {username}.")
    else:
        log_error(f"User {username} not found.")
    return False

def signup(username, password, email, role='user'):
    users = load_users()
    if username in users:
        return False
    hashed_password = hash_password(password)
    users[username] = {
        "password": hashed_password,
        "email": email,
        "role": role,
        "otp": None,
        "session_token": None,
        "expiry": None,
        "profile": {},
        "activity_log": []
    }
    save_users(users)
    log_activity(username, "signup")
    return True

def reset_password(username):
    users = load_users()
    if username in users:
        temp_password = secrets.token_hex(8)
        users[username]["password"] = hash_password(temp_password)
        save_users(users)
        log_activity(username, "reset_password")
        return temp_password
    return None

def update_profile(username, new_username, new_password, profile_info):
    users = load_users()
    if username in users:
        if new_username and new_username != username:
            users[new_username] = users.pop(username)
        if new_password:
            users[new_username]["password"] = hash_password(new_password)
        users[new_username]["profile"] = profile_info
        save_users(users)
        log_activity(new_username, "update_profile")
        return True
    return False

def get_user_role(username):
    users = load_users()
    if username in users:
        return users[username].get("role", "user")
    return None

def set_user_role(username, role):
    users = load_users()
    if username in users:
        users[username]["role"] = role
        save_users(users)
        log_activity(username, f"set_role_to_{role}")
        return True
    return False

def manage_device(username, device_info):
    devices = load_devices()
    if username not in devices:
        devices[username] = []
    devices[username].append(device_info)
    save_devices(devices)
    log_activity(username, "add_device", details=device_info)
    return True

def is_ip_whitelisted(ip_address):
    whitelisted_ips = load_whitelisted_ips()
    return ip_address in whitelisted_ips

def is_geo_blocked(location):
    blocked_geo = load_blocked_geo()
    return location in blocked_geo

def add_ip_to_whitelist(ip_address):
    whitelisted_ips = load_whitelisted_ips()
    if ip_address not in whitelisted_ips:
        whitelisted_ips.append(ip_address)
        save_whitelisted_ips(whitelisted_ips)
        log_info(f"Added IP address {ip_address} to whitelist.")
        return True
    return False

def block_geo_location(location):
    blocked_geo = load_blocked_geo()
    if location not in blocked_geo:
        blocked_geo.append(location)
        save_blocked_geo(blocked_geo)
        log_info(f"Blocked geographical location {location}.")
        return True
    return False
