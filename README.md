
# Zero Trust Authentication System

## Introduction

This project implements a Zero Trust Authentication System using Flask for the backend and Streamlit for the frontend. Zero Trust is a security model that assumes that threats can be both external and internal, and thus no entity (user, device, or application) should be trusted by default. This model enforces strict verification for every access attempt, regardless of the origin.

## Features

- **User Authentication**: Secure user authentication with password hashing and OTP (One-Time Password) verification.
- **Role-Based Access Control (RBAC)**: Different levels of access for users based on their roles.
- **Multi-Factor Authentication (MFA)**: OTP sent via email for an additional layer of security.
- **IP Whitelisting**: Access restricted to specified IP addresses.
- **Geo-Blocking**: Restricts access based on geographical location.
- **Device Management**: Manage devices associated with user accounts.
- **Activity Logs**: Logs of user activities for monitoring and auditing purposes.
- **Session Management**: Manage and validate active user sessions.

## Zero Trust Policies Implemented

1. **Multi-Factor Authentication (MFA)**
2. **IP Whitelisting**
3. **Geo-Blocking**
4. **Role-Based Access Control (RBAC)**
5. **Session Management**

### Multi-Factor Authentication (MFA)

MFA is implemented using OTP sent to the user's email. This adds an extra layer of security.

**Code Example:**
```python
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
            smtp_user = ##
            smtp_password = ##

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
```

### IP Whitelisting

Only requests from whitelisted IP addresses are allowed to proceed.

**Code Example:**
```python
def is_ip_whitelisted(ip_address):
    whitelisted_ips = load_whitelisted_ips()
    return ip_address in whitelisted_ips

@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        ip_address = get_ip_address()
        
        if not is_ip_whitelisted(ip_address):
            log_error(f"Login attempt from non-whitelisted IP: {ip_address}")
            return jsonify({"message": "Access denied from this IP address", "status": "error"}), 403
        
        # Further code...
    except Exception as e:
        log_error(f"An error occurred during login: {str(e)}")
        return jsonify({"message": "An error occurred. Please try again later.", "status": "error"}), 500
```

### Geo-Blocking

Access is restricted based on the geographical location of the user.

**Code Example:**
```python
def is_geo_blocked(location):
    blocked_geo = load_blocked_geo()
    return location in blocked_geo

@app.route('/api/login', methods=['POST'])
def api_login():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        ip_address = get_ip_address()
        location = get_geolocation(ip_address)
        
        if is_geo_blocked(location):
            log_error(f"Login attempt from blocked geographical location: {location}")
            return jsonify({"message": "Access denied from this geographical location", "status": "error"}), 403
        
        # Further code...
    except Exception as e:
        log_error(f"An error occurred during login: {str(e)}")
        return jsonify({"message": "An error occurred. Please try again later.", "status": "error"}), 500
```

### Role-Based Access Control (RBAC)

Users have different levels of access based on their roles (admin, user).

**Code Example:**
```python
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
```

### Session Management

Active user sessions are managed and validated to prevent unauthorized access.

**Code Example:**
```python
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
```

## Project Setup

### Prerequisites

- Python 3.7+
- Flask
- Streamlit
- Mailtrap Account for SMTP (or any other email service)

### Installation

1. **Create and activate a virtual environment:**
    ```sh
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

2. **Install the dependencies:**
    ```sh
    pip install -r requirements.txt
    ```

### Running the Project

1. **Start the Flask Server:**
    ```sh
    python server.py
    ```

2. **Start the Streamlit App:**
    ```sh
    streamlit run app.py
    ```

### Configuration

- **SMTP Configuration:** Update the SMTP configuration in `auth.py` with your Mailtrap (or other email service) credentials.
- **IP Whitelisting and Geo-Blocking:** Add necessary IP addresses and geographical locations to the `whitelisted_ips.json` and `blocked_geo.json` files respectively.

### Logging and Monitoring

Logging is configured to capture both informational and error messages to help in monitoring the application's performance and troubleshooting issues.

**Logger Configuration:**
```python
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s:%(message)s')

def log_info(message):
    logging.info(message)

def log_error(message):
    logging.error(message)
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please read the [CONTRIBUTING.md](CONTRIBUTING.md) file for guidelines on contributing to this project.

## Acknowledgments

- The developers of Flask and Streamlit for their excellent frameworks.
- Mailtrap for providing a reliable SMTP testing service.

---
