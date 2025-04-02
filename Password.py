"""
Password module for the Secure Role-Based Access System.

Handles:
- Password policy enforcement
- Password hashing and salting
- Credential verification
- Weak password checks using a blacklist

"""

import secrets
import hashlib
import Database as db


def check_password_policy(password: str) -> bool:
    """
    Validates the password against security policy requirements.

    Requirements:
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character (!, @, #, $, %, ?)
    - Length between 8 and 12 characters

    Args:
        password (str): The user's password.

    Returns:
        bool: True if the password meets all policy requirements, False otherwise.
    """
    if not (
        check_uppercase(password)
        and check_lowercase(password)
        and check_numericals(password)
        and check_specials(password)
        and (8 <= len(password) <= 12)
    ):
        return False

    print("✅ Password Creation Successful")
    return True


def check_uppercase(password: str) -> bool:
    """
    Checks if the password contains at least one uppercase character.

    Args:
        password (str): The password to check.

    Returns:
        bool: True if an uppercase letter exists, False otherwise.
    """
    return any(char.isupper() for char in password if char.isalpha())


def check_lowercase(password: str) -> bool:
    """
    Checks if the password contains at least one lowercase character.

    Args:
        password (str): The password to check.

    Returns:
        bool: True if a lowercase letter exists, False otherwise.
    """
    return any(char.islower() for char in password)


def check_numericals(password: str) -> bool:
    """
    Checks if the password contains at least one numeric digit.

    Args:
        password (str): The password to check.

    Returns:
        bool: True if a digit is present, False otherwise.
    """
    return any(char.isdigit() for char in password)


def check_specials(password: str) -> bool:
    """
    Checks if the password contains at least one special character.

    Valid special characters: {'!', '@', '#', '$', '%', '?'}

    Args:
        password (str): The password to check.

    Returns:
        bool: True if a special character exists, False otherwise.
    """
    special_characters = {"!", "@", "#", "$", "%", "?"}
    return any(char in special_characters for char in password)


def check_weak_password(password: str) -> bool:
    """
    Checks if the password is in the blacklist of commonly used passwords.

    Args:
        password (str): The password to check.

    Returns:
        bool: True if the password is weak (blacklisted), False otherwise.
    """
    return db.is_common_password(password)


def add_row(username: str, salt: int, hashcode: str, role: str) -> bool:
    """
    Adds a new user's credentials to the database.

    Args:
        username (str): The user's chosen username.
        salt (int): Salt used for password hashing.
        hashcode (str): The hashed password.
        role (str): The role assigned to the user.

    Returns:
        bool: True if the user was successfully added, False otherwise.
    """
    return db.add_user(username, salt, hashcode, role)


def generate_salt() -> int:
    """
    Generates a secure random salt using 30 bits of entropy.

    Returns:
        int: A pseudo-random integer to be used as a salt.
    """
    return secrets.randbits(30)


def hash_password(password: str, salt: int) -> str:
    """
    Hashes the given password using SHA-256 and a salt.

    Args:
        password (str): The raw user password.
        salt (int): The salt to append before hashing.

    Returns:
        str: The resulting hexadecimal hash string.
    """
    concat = f"{password} {salt}"
    return hashlib.sha256(concat.encode('utf-8')).hexdigest()


def check_user_login(username_input: str, password_input: str) -> bool:
    """
    Validates if the provided credentials match a user in the database.

    Args:
        username_input (str): Input username.
        password_input (str): Input password.

    Returns:
        bool: True if credentials are valid, False otherwise.
    """
    return db.check_credentials(username_input, password_input, hash_password)


def check_username_availability(username: str) -> bool:
    """
    Checks if the username is already taken.

    Args:
        username (str): The username to check.

    Returns:
        bool: True if username exists, False otherwise.
    """
    return db.is_username_taken(username)


def get_user_role(username_input: str, password_input: str) -> str:
    """
    Retrieves the role of the authenticated user.

    Args:
        username_input (str): Input username.
        password_input (str): Input password.

    Returns:
        str: The role of the user if credentials are valid, else None.
    """
    return db.get_user_role(username_input, password_input, hash_password)
