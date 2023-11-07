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
        if path is not None and excluded_paths is not None:
            for exclusion_path in map(lambda x: x.strip(), excluded_paths):
                pattern = ''
                if exclusion_path[-1] == '*':
                    pattern = '{}.*'.format(exclusion_path[0:-1])
                elif exclusion_path[-1] == '/':
                    pattern = '{}/*'.format(exclusion_path[0:-1])
                else:
                    pattern = '{}/*'.format(exclusion_path)
                if re.match(pattern, path):
                    return False
        return True

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
