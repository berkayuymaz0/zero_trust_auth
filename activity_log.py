import json
import time

users_db = "users.json"

def load_users():
    """Load user data from the JSON database."""
    try:
        with open(users_db, "r") as file:
            return json.load(file)
    except FileNotFoundError:
        return {}

def save_users(users):
    """Save user data to the JSON database."""
    with open(users_db, "w") as file:
        json.dump(users, file, indent=4)

def log_activity(username, action, details=None):
    """Log user activity with detailed context."""
    users = load_users()
    if username in users:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
        activity = {"action": action, "timestamp": timestamp}
        if details:
            activity["details"] = details
        users[username]["activity_log"].append(activity)
        save_users(users)
