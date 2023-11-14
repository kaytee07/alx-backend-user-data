#!/usr/bin/env python3
"""
hash password method that takes a password string arguments
and returns bytes.
"""
import bcrypt


def _hash_password(password):
    """
    accept a string as password and returns a hashed password in
    bytes

    Args:
        password: accept a string as a password

    Return:
         returns hashed password in bytes
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password
