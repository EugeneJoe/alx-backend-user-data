#!/usr/bin/env python3
"""
Defines a hash_password function to return a hashed password
"""
import bcrypt


def hash_password(password: str) -> str:
    """
    Returns a hashed password
    Args:
        password (str): password to be hashed
    """
    b = password.encode('ASCII')
    hashed = bcrypt.hashpw(b, bcrypt.gensalt())
    return hashed


def is_valid(hashed_password, password):
    """
    Check whether a password is valid
    Args:
        hashed_password (bytes): hashed password
        password (str): password in string
    Return:
        bool
    """
    if bcrypt.checkpw(password.encode('ASCII'), hashed_password):
        return True
    return False
