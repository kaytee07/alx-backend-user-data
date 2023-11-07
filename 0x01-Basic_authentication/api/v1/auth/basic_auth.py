#!/usr/bin/env python3
"""
basic_auth module
"""
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """
    Authentication with Basic Auth scheme
    """
    def extract_base64_authorization_header(self, authorization_header: str) -> str:
        """
        encode authorization_header with base64
        """
        if authorization_header is None:
            return None

        if type(authorization_header) is not str:
            return None

        parts = authorization_header.split(' ')
        if parts[0] != 'Basic':
            return None
        else:
            return parts[1]
