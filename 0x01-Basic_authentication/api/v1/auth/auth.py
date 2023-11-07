#!/usr/bin/env python3
"""
auth module
"""
from flask import request
from typing import List, TypeVar


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

        if excluded_paths is None or len(excluded_paths) == 0:
            return True

        normalized_path = path.rstrip('/')
        normalized_excluded_path = [p.rstrip('/') for p in excluded_paths]
        if normalized_path in normalized_excluded_path:
            return False
        else:
            return True

        return False

    def current_user(self, request=None) -> TypeVar('User'):
        """
        get current user
        """
        return None


    def authorization_header(self, request=None) -> str:
        """
        authorization_header
        """
        print(request)
        if request is None:
            return None

        if 'Authorization' not in request.headers:
            return None
        else:
            return request.headers.get('Authorization')
        
        return None
