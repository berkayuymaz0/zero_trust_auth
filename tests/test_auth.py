import unittest
import os
import json
import secrets
import time
from auth import hash_password, check_password, signup, login, reset_password, update_profile, get_user_role, set_user_role, get_active_sessions, save_users, load_users

class TestAuth(unittest.TestCase):

    def setUp(self):
        # Clear the users database before each test
        if os.path.exists("users.json"):
            os.remove("users.json")
        save_users({})

    def tearDown(self):
        # Clean up after each test
        if os.path.exists("users.json"):
            os.remove("users.json")

    def test_hash_password(self):
        password = "password123"
        hashed = hash_password(password)
        self.assertNotEqual(password, hashed)
        self.assertTrue(check_password(hashed, password))

    def test_signup_and_login(self):
        username = "testuser"
        password = "password123"
        self.assertTrue(signup(username, password))
        self.assertTrue(login(username, password))

    def test_reset_password(self):
        username = "testuser"
        self.assertTrue(signup(username, "password123"))
        temp_password = reset_password(username)
        self.assertIsNotNone(temp_password)
        self.assertTrue(login(username, temp_password))

    def test_update_profile(self):
        username = "testuser"
        new_username = "updateduser"
        new_password = "newpassword123"
        self.assertTrue(signup(username, "password123"))
        self.assertTrue(update_profile(username, new_username, new_password, {"info": "Test"}))
        self.assertTrue(login(new_username, new_password))

    def test_user_roles(self):
        username = "testuser"
        self.assertTrue(signup(username, "password123"))
        role = get_user_role(username)
        self.assertEqual(role, "user")
        self.assertTrue(set_user_role(username, "admin"))
        self.assertEqual(get_user_role(username), "admin")

    def test_active_sessions(self):
        username = "testuser"
        self.assertTrue(signup(username, "password123"))
        session_token = secrets.token_hex(16)
        expiry = int(time.time()) + 3600
        users = load_users()
        users[username]["session_token"] = session_token
        users[username]["expiry"] = expiry
        save_users(users)
        sessions = get_active_sessions()
        self.assertIn(username, [session['username'] for session in sessions])

if __name__ == '__main__':
    unittest.main()
