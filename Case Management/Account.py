from db_connect import DatabaseManager
import hashlib

class Account:
    def __init__(self, db_manager, username=None, password=None, role=None):
        self.db_manager = db_manager
        self.username = username
        self.password = self._hash_password(password) if password else None
        self.role = role
    
    def _hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()
    
    def authenticate(self, username, password):
        query = "SELECT * FROM users WHERE username = %s AND password = %s"
        hashed_password = self._hash_password(password)
        return self.db_manager.fetch_one(query, (username, hashed_password)) is not None
