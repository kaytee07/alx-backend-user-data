#!/usr/bin/env python3
"""
hash password method that takes a password string arguments
and returns bytes.
"""
import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
import uuid


def _hash_password(password: str) -> bytes:
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

def _generate_uuid(self):
        """
        generate uuid and return it as a string
        """
        generated_uuid = uuid.uuid4()
        return str(generated_uuid)


class Auth:
    """
    Auth class to interact with the authentication database.,
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password:str) -> User:
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

    def valid_login(self, email, password):
        """
        validate user credentials

        Args:
            email: user email
            password: user password

        Return:
             True if user email and pass exist in db else false
        """
        try:
            user = self._db.find_user_by(email=email)
            is_matching = bcrypt.checkpw(password.encode('utf-8'),
                                         user.hashed_password)
            if is_matching:
                return True
            return False
        except NoResultFound:
            return False
        return False

    def create_session(self, email):
        """
        create session_id
        """
        try:
            user = self._db.find_user_by(email=email)
            generated_uuid = self._generate_uuid()
            self._db.update_user(user.id, session_id=generated_uuid)
            return user.session_id
        except NoResultFound:
            return

    def get_user_from_session_id(self, session_id):
        """
        takes session_id and returns the user
        """
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None
        return None

    def destroy_session(self, user_id):
        """
        set session_id of a user to None
        """
        user = self._db.update_user(user_id, session_id=None)
        return None

    def get_reset_password_token(self, email):
        """
        get reset password token
        """
        user = self._db.find_user_by(session_id=session_id)
        if user is None:
            raise ValueError
        token = self._generate_uuid()
        self._db.update_user(user.id, reset_token=token)
        return user.reset_token

    def update_password(self, reset_token, password):
        """
        update password in database with reset token
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            hashed_password = _hash_password(password)
            self._db.update_user(user.id,
                                 password=hashed_password)
            self._db.update_user(user.id, reset_token=None)
        except NoResultFound:
            raise ValueError
        return None
