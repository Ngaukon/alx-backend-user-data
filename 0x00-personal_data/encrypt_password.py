#!/usr/bin/env python3
"""A module for encrypting and verifying passwords using bcrypt.
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """Hashes a password with a randomly generated salt.

    Args:
        password (str): The plaintext password to hash.

    Returns:
        bytes: The resulting hashed password in bytes, with the salt included.
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Verifies that a password matches its hashed version.

    Args:
        hashed_password (bytes): The hashed password to check against.
        password (str): The plaintext password to verify.

    Returns:
        bool: True if the password matches the hashed version; False otherwise.
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
