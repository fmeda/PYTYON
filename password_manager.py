# password_manager.py

import hashlib
import os

class PasswordManager:
    def __init__(self):
        self.salt = os.urandom(16)

    def hash_password(self, password):
        return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), self.salt, 100000)
