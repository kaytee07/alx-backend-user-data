#!/usr/bin/env python3
"""
hash password method that takes a password string arguments
and returns bytes.
"""
import bcrypt
from db import DB
from sqlalchemy.orm.exc import NoResultFound


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


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email, password):
        """
        add new user to the database
        """
        if password is None or email is None:
            return
        try:
            user = self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            hashed_password = _hash_password(password)
            registered_user = self._db.add_user(email, hashed_password)
            return registered_user
