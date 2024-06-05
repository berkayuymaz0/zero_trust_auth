from flask import Flask, request, jsonify
from auth import load_users, save_users, login, signup, reset_password, update_profile, generate_otp, get_time_remaining, send_otp_email, verify_otp, manage_device, is_ip_whitelisted, is_geo_blocked
from logger import log_info, log_error
from utils import get_ip_address, get_geolocation

app = Flask(__name__)

@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        ip_address = get_ip_address()
        location = get_geolocation(ip_address)
        
        if not is_ip_whitelisted(ip_address):
            log_error(f"Login attempt from non-whitelisted IP: {ip_address}")
            return jsonify({"message": "Access denied from this IP address", "status": "error"}), 403
        
        if is_geo_blocked(location):
            log_error(f"Login attempt from blocked geographical location: {location}")
            return jsonify({"message": "Access denied from this geographical location", "status": "error"}), 403

        log_info(f"Login attempt for user {username} from IP {ip_address} and location {location}.")
        if login(username, password):
            otp = generate_otp()
            users = load_users()
            users[username]['otp'] = otp
            save_users(users)
            if send_otp_email(username, otp):
                log_info(f"OTP sent to {username}.")
                return jsonify({"otp": otp, "status": "success"}), 200
        log_error(f"Failed login attempt for {username}.")
        return jsonify({"message": "Invalid credentials", "status": "error"}), 401
    except Exception as e:
        log_error(f"An error occurred during login: {str(e)}")
        return jsonify({"message": "An error occurred. Please try again later.", "status": "error"}), 500

@app.route('/api/verify_otp', methods=['POST'])
def api_verify_otp():
    try:
        data = request.json
        username = data.get('username')
        otp_input = data.get('otp')
        if verify_otp(username, otp_input):
            log_info(f"OTP verified for {username}.")
            return jsonify({"status": "success"}), 200
        log_error(f"Invalid OTP for {username}.")
        return jsonify({"status": "error"}), 401
    except Exception as e:
        log_error(f"An error occurred during OTP verification: {str(e)}")
        return jsonify({"message": "An error occurred. Please try again later.", "status": "error"}), 500

@app.route('/api/signup', methods=['POST'])
def api_signup():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')
        if signup(username, password, email):
            log_info(f"User {username} signed up successfully.")
            return jsonify({"status": "success"}), 200
        log_error(f"Failed signup attempt for {username}. Username already exists.")
        return jsonify({"message": "Username already exists", "status": "error"}), 400
    except Exception as e:
        log_error(f"An error occurred during signup: {str(e)}")
        return jsonify({"message": "An error occurred. Please try again later.", "status": "error"}), 500

@app.route('/api/reset_password', methods=['POST'])
def api_reset_password():
    try:
        data = request.json
        username = data.get('username')
        temp_password = reset_password(username)
        if temp_password:
            log_info(f"Password reset for {username}.")
            return jsonify({"temp_password": temp_password, "status": "success"}), 200
        log_error(f"Password reset attempt failed for {username}. Username not found.")
        return jsonify({"message": "Username not found", "status": "error"}), 404
    except Exception as e:
        log_error(f"An error occurred during password reset: {str(e)}")
        return jsonify({"message": "An error occurred. Please try again later.", "status": "error"}), 500

@app.route('/api/device_management', methods=['POST'])
def api_device_management():
    try:
        data = request.json
        username = data.get('username')
        device_info = data.get('device_info')
        if manage_device(username, device_info):
            log_info(f"Device added for {username}.")
            return jsonify({"status": "success"}), 200
        log_error(f"Failed to add device for {username}.")
        return jsonify({"status": "error"}), 400
    except Exception as e:
        log_error(f"An error occurred during device management: {str(e)}")
        return jsonify({"message": "An error occurred. Please try again later.", "status": "error"}), 500

if __name__ == '__main__':
    app.run(debug=True)
