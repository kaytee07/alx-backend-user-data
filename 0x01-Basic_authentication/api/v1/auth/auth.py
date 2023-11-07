#!/usr/bin/env python3
"""
auth module
"""
from flask import request


class Auth:
    """
    authenticate
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """"
        path that require authentication
        
        Args:
            path: path that require authentication
        
            excluded_paths: path that dont require auth
        
        returns: False
        """
        return False


    def current_user(self, request=None) -> TypeVar('User'):
        """
        get current user
        """


    def authorization_header(self, request=None) -> str:
        """
        authorization_header
        """
        return None
