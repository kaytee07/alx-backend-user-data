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


def _generate_uuid() -> str:
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

    def register_user(self, email: str, password: str) -> User:
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

    def valid_login(self, email: str, password: str) -> bool:
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

    def create_session(self, email: str) -> str:
        """
        create session_id
        """
        user = None
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        if user is None:
            return None
        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> User:
        """
        takes session_id and returns the user
        """
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None
        return None

    def destroy_session(self, user_id: str) -> None:
        """
        set session_id of a user to None
        """
        if user_id is None:
            return None
        user = self._db.update_user(user_id, session_id=None)

    def get_reset_password_token(self, email: str) -> str:
        """
        get reset password token
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError()
        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
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
            raise ValueError()
        return None
