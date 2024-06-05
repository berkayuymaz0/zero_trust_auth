import streamlit as st
import secrets
import time
import requests
from utils import load_json, save_json, check_password_strength, create_session, validate_session as utils_validate_session, clear_session, get_active_sessions
from logger import log_info, log_error
from auth import get_time_remaining, update_profile, get_user_role, set_user_role

st.set_page_config(page_title="Secure App", page_icon="🔐", layout="wide")

API_URL = "http://127.0.0.1:5000/api"

if 'theme' not in st.session_state:
    st.session_state['theme'] = 'dark'

def toggle_theme():
    if st.session_state['theme'] == 'dark':
        st.session_state['theme'] = 'light'
    else:
        st.session_state['theme'] = 'dark'

def set_session(username):
    session_token, expiry = create_session(username)
    st.session_state['session_token'] = session_token
    st.session_state['username'] = username
    st.session_state['expiry'] = expiry

def validate_current_session():
    if 'session_token' in st.session_state and 'username' in st.session_state and 'expiry' in st.session_state:
        username = utils_validate_session(st.session_state['session_token'])
        if username:
            return True
    return False

def clear_current_session():
    if 'session_token' in st.session_state:
        clear_session(st.session_state['session_token'])
        st.session_state.pop('session_token', None)
        st.session_state.pop('username', None)
        st.session_state.pop('expiry', None)

def main():
    if st.session_state['theme'] == 'dark':
        st.markdown(
            """
            <style>
            body {
                background-color: #333;
                color: #fff;
            }
            </style>
            """,
            unsafe_allow_html=True,
        )
    
    st.title("Secure App")

    if validate_current_session():
        role = get_user_role(st.session_state['username'])
        st.sidebar.write(f"Welcome, {st.session_state['username']}!")
        if role == "admin":
            menu = ["Profile", "Manage Sessions", "Manage Users", "Device Management", "Activity Logs", "Logout"]
        else:
            menu = ["Profile", "Manage Sessions", "Device Management", "Activity Logs", "Logout"]
    else:
        menu = ["Login", "Sign Up"]
    
    choice = st.sidebar.selectbox("Menu", menu)

    if choice == "Login":
        if validate_current_session():
            st.warning("You are already logged in.")
            st.stop()
        st.subheader("Login")
        username = st.text_input("Username", placeholder="Enter your username")
        password = st.text_input("Password", type='password', placeholder="Enter your password")

        if st.button("Login"):
            with st.spinner("Logging in..."):
                response = requests.post(f"{API_URL}/login", json={"username": username, "password": password})
                if response.status_code == 200:
                    otp = response.json().get('otp')
                    st.session_state["pending_username"] = username
                    st.session_state["otp"] = otp
                    requests.post(f"{API_URL}/send_otp", json={"username": username})
                    st.experimental_rerun()
                else:
                    try:
                        error_message = response.json().get('message', "Invalid Username or Password")
                    except ValueError:
                        error_message = "An error occurred. Please try again."
                    st.error(error_message)

        if st.button("Forgot Password"):
            if username:
                response = requests.post(f"{API_URL}/reset_password", json={"username": username})
                if response.status_code == 200:
                    temp_password = response.json().get('temp_password')
                    st.success(f"Temporary password: {temp_password}")
                else:
                    try:
                        error_message = response.json().get('message', "Username not found")
                    except ValueError:
                        error_message = "An error occurred. Please try again."
                    st.error(error_message)
            else:
                st.error("Please enter your username")

    if "pending_username" in st.session_state:
        otp = st.session_state["otp"]
        st.subheader("Enter OTP")
        st.info(f"Your OTP is: {otp}")
        
        otp_input = st.text_input("OTP", type='password', placeholder="Enter the OTP displayed above")
        time_remaining = get_time_remaining()
        
        st.markdown(f"**Time remaining for OTP:** {time_remaining} seconds")
        
        if st.button("Verify OTP"):
            response = requests.post(f"{API_URL}/verify_otp", json={"username": st.session_state["pending_username"], "otp": otp_input})
            if response.status_code == 200:
                set_session(st.session_state["pending_username"])
                del st.session_state["pending_username"]
                del st.session_state["otp"]
                st.experimental_rerun()
            else:
                try:
                    error_message = response.json().get('message', "Incorrect OTP")
                except ValueError:
                    error_message = "An error occurred. Please try again."
                st.error(error_message)

    elif choice == "Sign Up":
        if validate_current_session():
            st.warning("You are already logged in.")
            st.stop()
        st.subheader("Create New Account")
        new_username = st.text_input("New Username", placeholder="Choose a username")
        new_password = st.text_input("New Password", type='password', placeholder="Choose a password")
        email = st.text_input("Email", placeholder="Enter your email")

        if new_password:
            password_strength, color = check_password_strength(new_password)
            st.markdown(f"**Password Strength:** <span style='color:{color}'>{password_strength}</span>", unsafe_allow_html=True)

        if st.button("Sign Up"):
            with st.spinner("Creating account..."):
                response = requests.post(f"{API_URL}/signup", json={"username": new_username, "password": new_password, "email": email})
                if response.status_code == 200:
                    st.success("You have successfully created an account")
                else:
                    try:
                        error_message = response.json().get('message', "Username already exists")
                    except ValueError:
                        error_message = "An error occurred. Please try again."
                    st.warning(error_message)

    elif choice == "Profile":
        if not validate_current_session():
            st.warning("You need to log in to view this page.")
            st.stop()
        st.subheader("Profile Page")
        new_username = st.text_input("New Username", placeholder="Update your username")
        new_password = st.text_input("New Password", type='password', placeholder="Update your password")
        profile_info = st.text_area("Profile Information", placeholder="Enter additional profile information")

        if st.button("Update Profile"):
            with st.spinner("Updating profile..."):
                if update_profile(st.session_state["username"], new_username, new_password, profile_info):
                    st.success("Profile updated successfully")
                    if new_username:
                        st.session_state["username"] = new_username
                else:
                    st.error("An error occurred while updating the profile")

    elif choice == "Manage Sessions":
        if not validate_current_session():
            st.warning("You need to log in to view this page.")
            st.stop()
        st.subheader("Manage Active Sessions")
        active_sessions = get_active_sessions()
        for session in active_sessions.values():
            st.write(f"Username: {session['username']}, Expiry: {time.ctime(session['expiry'])}")

    elif choice == "Manage Users":
        if role != "admin":
            st.warning("You do not have permission to view this page.")
            st.stop()
        st.subheader("Manage Users")
        users = load_json("data/users.json")
        for user in users:
            st.write(f"Username: {user}, Role: {users[user]['role']}")
            col1, col2 = st.columns(2)
            with col1:
                if st.button(f"Make Admin {user}"):
                    set_user_role(user, "admin")
                    st.success(f"{user} is now an admin.")
            with col2:
                if st.button(f"Make User {user}"):
                    set_user_role(user, "user")
                    st.success(f"{user} is now a user.")

    elif choice == "Device Management":
        if not validate_current_session():
            st.warning("You need to log in to view this page.")
            st.stop()
        st.subheader("Device Management")
        device_info = st.text_input("Device Info", placeholder="Enter your device info")
        if st.button("Add Device"):
            with st.spinner("Adding device..."):
                response = requests.post(f"{API_URL}/device_management", json={"username": st.session_state["username"], "device_info": device_info})
                if response.status_code == 200:
                    st.success("Device added successfully")
                else:
                    st.error("An error occurred while adding the device")

    elif choice == "Activity Logs":
        if not validate_current_session():
            st.warning("You need to log in to view this page.")
            st.stop()
        st.subheader("Activity Logs")
        users = load_json("data/users.json")
        if st.session_state['username'] in users:
            activity_logs = users[st.session_state['username']].get('activity_log', [])
            for log in activity_logs:
                st.write(f"{log['timestamp']}: {log['action']}")

    elif choice == "Logout":
        clear_current_session()
        st.success("You have successfully logged out.")
        st.experimental_rerun()

if __name__ == '__main__':
    main()
