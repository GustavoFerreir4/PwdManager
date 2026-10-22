from cryptography.fernet import Fernet as f
import sqlite3
import json

#autenticador deve receber um usuário e uma senha
#vai criptografar ambos com a chave pública dada.
class Authenticator:

    def __init__(self, user:str, passwd:str):
        self.masterSessionKey = f.generate_key()
        self.fernet = f(self.masterSessionKey)
        self.user = user
        self.passwd = self.fernet.encrypt(bytes(passwd, encoding="UTF-8"))

    def _login(self):
        if self.user_exists():
          pass  
        

    def _register(self, data:str):
        if not self.user_exists():
            
            pass

    def user_exists(self, userName:str) -> bool:

        db = SqlClient()
        users = db.get_users()
        userExists = False

        for i in users:
            if i[0] == userName:
                userExists = True
                break

        if userExists:
            return True

        return False

class SqlClient:
    def __init__(self, db_name="vault.db"):
        self.db_name = db_name
        self.init_database()

    def get_connection(self):
        """Creates and returns a database connection."""
        return sqlite3.connect(self.db_name)

    def init_database(self):
        """Creates the initial tables if they don't already exist."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.executescript("""
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    username TEXT NOT NULL,
                    encrypted_data TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    masterpwd TEXT NOT NULL
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            conn.commit()

    def add_credential(self, title, username, encrypted_data):
        """Inserts a new encrypted credential record."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO credentials (title, username, encrypted_data)
                VALUES (?, ?, ?)
            """, (title, username, encrypted_data))
            conn.commit()

    def get_all_credentials(self):
        """Fetches all records from the database."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, title, username, encrypted_data FROM credentials")
            return cursor.fetchall()

    def get_credentials_from_user(self, userName:str):
        if not userName:
            return "ACTION DID NOT SUCCEED: Invalid userName"
            
        with self.get_connection() as conn:

            cursor = conn.cursor()
            cursor.execute(f"""

            SELECT * FROM credentials
            WHERE username = {userName}
            
            """)
            conn.commit()
            return cursor.fetchall()

    def remove_credential(self, id:int=None):
        if not id:
            return "ACTION DID NOT SUCCEED: Invalid id"
        with self.get_connection() as conn:

            cursor = conn.cursor()
            cursor.execute(f"""

            DELETE FROM credentials
            WHERE id = {id}
            
            """)
            conn.commit()

    def get_users(self):
        if not id:
            return "ACTION DID NOT SUCCEED: Invalid id"
        with self.get_connection() as conn:

            cursor = conn.cursor()
            cursor.execute(f"""

            SELECT username FROM users
            
            """)
            conn.commit()
            return cursor.fetchall



