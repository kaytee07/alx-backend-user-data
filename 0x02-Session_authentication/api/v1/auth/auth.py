#!/usr/bin/env python3
"""
auth module
"""
from flask import request
from typing import List, TypeVar
import os


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
        if path is None:
            return True

        if excluded_paths is None or excluded_paths == []:
            return True

        if path in excluded_paths:
            return False

        for excluded_path in excluded_paths:
            if excluded_path.startswith(path):
                return False
            elif path.startswith(excluded_path):
                return False
            elif excluded_path[-1] == "*":
                if path.startswith(excluded_path[:-1]):
                    return False

        return True

    def authorization_header(self, request=None) -> str:
        """
        Gets the authorization header field from the request.
        """
        print(request)
        if request is None:
            return None

        if 'Authorization' not in request.headers:
            return None
        else:
            return request.headers.get('Authorization')

        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        get current user
        """
        return None

    def session_cookie(self, request=None):
        """
        return a cookie value from a request
        """
        if request is None:
            return None

        cookie_name = os.getenv('SESSION_NAME')
        session_name = request.cookies.get(cookie_name)
        return session_name
