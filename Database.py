"""
Database module for user authentication and password validation system.

Handles all interaction with the SQLite database, including:
- User creation and lookup
- Storing and checking weak passwords
- Verifying login credentials

"""

import sqlite3
from pathlib import Path
import os
from typing import Optional, Tuple, List

# Absolute path to the SQLite database file (project-local)
DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")


def get_connection() -> sqlite3.Connection:
    """
    Establishes and returns a connection to the SQLite database.

    Returns:
        sqlite3.Connection: Active database connection object.
    """
    return sqlite3.connect(DB_PATH)


def init_db() -> None:
    """
    Initializes the SQLite database by creating the required tables if they don't exist.
    - users: stores username, password hash, salt, and role.
    - bad_passwords: stores a blacklist of weak/common passwords.
    """
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                salt INTEGER NOT NULL,
                hashcode TEXT NOT NULL,
                role TEXT NOT NULL
            )
        ''')
        cur.execute('''
            CREATE TABLE IF NOT EXISTS bad_passwords (
                password TEXT PRIMARY KEY
            )
        ''')
        conn.commit()


def add_user(username: str, salt: int, hashcode: str, role: str) -> bool:
    """
    Inserts a new user into the database.

    Args:
        username (str): Chosen username (must be unique).
        salt (int): Randomly generated salt for hashing.
        hashcode (str): SHA-256 hashed password with salt.
        role (str): Role assigned to the user.

    Returns:
        bool: True if the user was added successfully, False if the username already exists.
    """
    with get_connection() as conn:
        cur = conn.cursor()
        try:
            cur.execute(
                'INSERT INTO users (username, salt, hashcode, role) VALUES (?, ?, ?, ?)',
                (username, salt, hashcode, role)
            )
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False


def get_user(username: str) -> Optional[Tuple[str, int, str, str]]:
    """
    Retrieves a user's record from the database.

    Args:
        username (str): Username to look up.

    Returns:
        tuple or None: Tuple of (username, salt, hashcode, role) if found; None otherwise.
    """
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            'SELECT username, salt, hashcode, role FROM users WHERE username = ?', (username,)
        )
        return cur.fetchone()


def is_username_taken(username: str) -> bool:
    """
    Checks if a username is already registered.

    Args:
        username (str): Username to check.

    Returns:
        bool: True if taken, False otherwise.
    """
    return get_user(username) is not None


def check_credentials(username_input: str, password_input: str, hash_function) -> bool:
    """
    Validates user login credentials.

    Args:
        username_input (str): Input username.
        password_input (str): Input password.
        hash_function (Callable): Function to hash the password with salt.

    Returns:
        bool: True if credentials are valid, False otherwise.
    """
    user = get_user(username_input)
    if user:
        _, salt, stored_hash, _ = user
        computed_hash = hash_function(password_input, salt)
        return computed_hash == stored_hash
    return False


def get_user_role(username_input: str, password_input: str, hash_function) -> Optional[str]:
    """
    Retrieves the role of the user after verifying credentials.

    Args:
        username_input (str): Input username.
        password_input (str): Input password.
        hash_function (Callable): Hashing function for password + salt.

    Returns:
        str or None: The user's role if credentials are correct, else None.
    """
    user = get_user(username_input)
    if user:
        _, salt, stored_hash, role = user
        if hash_function(password_input, salt) == stored_hash:
            return role
    return None


def load_bad_passwords(filepath: str) -> None:
    """
    Loads a list of weak/common passwords into the database from a text file.

    Args:
        filepath (str): Path to the bad passwords file (one password per line).
    """
    if not Path(filepath).exists():
        return
    with open(filepath, 'r') as file, get_connection() as conn:
        passwords = [(line.strip(),) for line in file if line.strip()]
        cur = conn.cursor()
        cur.executemany(
            'INSERT OR IGNORE INTO bad_passwords (password) VALUES (?)',
            passwords
        )
        conn.commit()


def is_common_password(password: str) -> bool:
    """
    Checks if a given password exists in the bad password blacklist.

    Args:
        password (str): The password to check.

    Returns:
        bool: True if password is blacklisted, False otherwise.
    """
    with get_connection() as conn:
        cur = conn.cursor()
        cur.execute('SELECT 1 FROM bad_passwords WHERE password = ?', (password,))
        return cur.fetchone() is not None
