import streamlit as st
import requests

FLASK_SERVER_URL = "http://127.0.0.1:5000"

def fetch_logs():
    response = requests.get(f"{FLASK_SERVER_URL}/logs")
    if response.status_code == 200:
        return response.json()['logs']
    else:
        return ["Error fetching logs"]

def main():
    st.set_page_config(page_title="Auth App", page_icon="🔒", layout="wide")

    if 'username' not in st.session_state:
        st.session_state.username = None

    def login(username):
        st.session_state.username = username

    def logout():
        st.session_state.username = None
        requests.post(f"{FLASK_SERVER_URL}/logout")

    st.sidebar.title("Navigation")
    if st.session_state.username:
        st.sidebar.write(f"Logged in as {st.session_state.username}")
        menu = ["View Logs", "Profile", "Reset Password", "Logout"]
    else:
        menu = ["Login", "SignUp"]
    choice = st.sidebar.selectbox("Select an option", menu)

    if choice == "Login":
        st.subheader("Login Section")
        with st.form(key='login_form'):
            username = st.text_input("Username")
            password = st.text_input("Password", type='password')
            submit_button = st.form_submit_button(label="Login")

        if submit_button:
            with st.spinner('Authenticating...'):
                response = requests.post(f"{FLASK_SERVER_URL}/login", json={"username": username, "password": password})
            if response.status_code == 200:
                st.success(response.json()['message'])
                login(username)
            else:
                st.error(response.json()['message'])

    elif choice == "SignUp":
        st.subheader("Create New Account")
        with st.form(key='signup_form'):
            new_user = st.text_input("Username")
            new_password = st.text_input("Password", type='password')
            submit_button = st.form_submit_button(label="SignUp")

        if submit_button:
            with st.spinner('Creating account...'):
                response = requests.post(f"{FLASK_SERVER_URL}/signup", json={"username": new_user, "password": new_password})
            if response.status_code == 201:
                st.success(response.json()['message'])
                st.info("Go to Login Menu to login")
            else:
                st.warning(response.json()['message'])

    elif choice == "View Logs":
        st.subheader("Logs")
        logs = fetch_logs()
        st.text_area("Logs", value="\n".join(logs), height=400)

    elif choice == "Profile":
        st.subheader("Update Profile")
        with st.form(key='profile_form'):
            new_password = st.text_input("New Password", type='password')
            submit_button = st.form_submit_button(label="Update Profile")

        if submit_button:
            with st.spinner('Updating profile...'):
                response = requests.post(f"{FLASK_SERVER_URL}/update_profile", json={"new_password": new_password})
            if response.status_code == 200:
                st.success(response.json()['message'])
            else:
                st.error(response.json()['message'])

    elif choice == "Reset Password":
        st.subheader("Reset Password")
        with st.form(key='reset_password_form'):
            username = st.text_input("Username")
            new_password = st.text_input("New Password", type='password')
            submit_button = st.form_submit_button(label="Reset Password")

        if submit_button:
            with st.spinner('Resetting password...'):
                response = requests.post(f"{FLASK_SERVER_URL}/reset_password", json={"username": username, "new_password": new_password})
            if response.status_code == 200:
                st.success(response.json()['message'])
            else:
                st.error(response.json()['message'])

    elif choice == "Logout":
        st.subheader("Logout")
        logout()
        st.success("Logged out successfully")

if __name__ == '__main__':
    main()
