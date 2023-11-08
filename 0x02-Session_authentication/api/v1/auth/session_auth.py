#!/usr/bin/env python3
"""
session_auth module
"""
from api.v1.auth.auth import Auth
import uuid

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
        if type(session_id) is str:
            user_id = self.user_id_by_session_id.get(session_id)
            return user_id
        return None

