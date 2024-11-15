#!/usr/bin/env python3
"""
Basic authentication module for the API.

This module defines a `BasicAuth` class that extends the `Auth` class
to implement Basic Authentication using the `Authorization` header.
"""
import re
import base64
import binascii
from typing import Tuple, TypeVar

from .auth import Auth
from models.user import User


class BasicAuth(Auth):
    """Basic authentication class.

    Provides methods to handle Basic Authentication, including extracting,
    decoding, and validating user credentials.
    """
    def extract_base64_authorization_header(
            self,
            authorization_header: str) -> str:
        """
        Extracts the Base64-encoded token from the Authorization header.

        Args:
            authorization_header (str): The Authorization header value.

        Returns:
            str: The Base64-encoded token if present, None otherwise.
        """
        if type(authorization_header) == str:
            pattern = r'Basic (?P<token>.+)'
            field_match = re.fullmatch(pattern, authorization_header.strip())
            if field_match is not None:
                return field_match.group('token')
        return None

    def decode_base64_authorization_header(
            self,
            base64_authorization_header: str) -> str:
        """
        Decodes the Base64-encoded authorization token.

        Args:
            base64_authorization_header (str): The Base64-encoded token.

        Returns:
            str: The decoded string if successful, None otherwise.
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
            decoded_base64_authorization_header: str) -> Tuple[str, str]:
        """
        Extracts the user email and password from the decoded Base64 token.

        Args:
            decoded_base64_authorization_header (str): The decoded token.

        Returns:
            Tuple[str, str]: A tuple containing the email and password, 
            or (None, None) if the token is invalid.
        """
        if type(decoded_base64_authorization_header) == str:
            pattern = r'(?P<user>[^:]+):(?P<password>.+)'
            field_match = re.fullmatch(
                pattern,
                decoded_base64_authorization_header.strip(),
            )
            if field_match is not None:
                user = field_match.group('user')
                password = field_match.group('password')
                return user, password
        return None, None

    def user_object_from_credentials(
            self,
            user_email: str,
            user_pwd: str) -> TypeVar('User'):
        """
        Retrieves a user object based on the provided email and password.

        Args:
            user_email (str): The user's email address.
            user_pwd (str): The user's password.

        Returns:
            User: The authenticated user object if credentials are valid, 
            None otherwise.
        """
        if type(user_email) == str and type(user_pwd) == str:
            try:
                users = User.search({'email': user_email})
            except Exception:
                return None
            if len(users) <= 0:
                return None
            if users[0].is_valid_password(user_pwd):
                return users[0]
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the current user based on the request.

        This method extracts and decodes the Authorization header, extracts
        the user's credentials, and retrieves the corresponding user object.

        Args:
            request (flask.Request): The Flask request object.

        Returns:
            User: The authenticated user object if valid, None otherwise.
        """
        auth_header = self.authorization_header(request)
        b64_auth_token = self.extract_base64_authorization_header(auth_header)
        auth_token = self.decode_base64_authorization_header(b64_auth_token)
        email, password = self.extract_user_credentials(auth_token)
        return self.user_object_from_credentials(email, password)
