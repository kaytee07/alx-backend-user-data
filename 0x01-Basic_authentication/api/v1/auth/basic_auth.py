#!/usr/bin/env python3
"""
basic_auth module
"""
from api.v1.auth.auth import Auth
import binascii
import base64


class BasicAuth(Auth):
    """
    Authentication with Basic Auth scheme
    """
    def extract_base64_authorization_header(
            self,
            authorization_header: str) -> str:
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

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str) -> str:
        """
        Decodes a base64-encoded authorization header.
        """
        if type(base64_authorization_header) == str:
            try:
                res = base64.b64decode(
                    base64_authorization_header,
                    validate=True,
                )
                return res.decode('utf-8')
            except (binascii.Error, UnicodeDecodeError):
                return None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str) -> (str, str):
        """
        returns the user email and password from the
        Base64 decoded value.
        """
        if decoded_base64_authorization_header is None:
            return (None, None)

        if type(decoded_base64_authorization_header) != str:
            return (None, None)

        if ':' in decoded_base64_authorization_header:
            parts = decoded_base64_authorization_header.split(':')
            return (parts[0], parts[1])
        else:
            return (None, None)
