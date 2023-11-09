#!/usr/bin/env python3
"""
session_auth module
"""
from .auth import Auth
import uuid
from models.user import User

class SessionAuth(Auth):
    """
    session_authentication
    """
    user_id_by_session_id = {}

    def create_session(self, user_id: str = None) -> str:
        """
        creates a session_id for a user
        """
        
        if type(user_id) is str:
            session_id = uuid.uuid4().hex
            self.user_id_by_session_id[session_id] = user_id
            return session_id
        
        return None

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """
        return a User ID based on session id
        """
        if session_id is None:
            return None
        if type(session_id) is str:
            user_id = self.user_id_by_session_id.get(session_id)
            return user_id

        return None

    def current_user(self, request=None):
        """
        returns a user instance based on cookie value
        """
        session_id = self.session_cookie(request)
        user_id = self.user_id_for_session_id(session_id)
        if user_id is None:
            return None
        return User(user_id)

    def destroy_session(self, request=None):
        """
        destroy a session
        """
        if request is None:
            return False

        session_id = self.session_cookie(request)
        if session_id is None:
            return False
        
        user_id = self.user_id_for_session_id(session_id)
        print(user_id)
        if user_id is None:
            return False

        del self.user_id_by_session_id[session_id]
