#!/usr/bin/env python3
"""
Authentication module for the API.

This module defines a base `Auth` class for handling authentication-related
logic, such as checking if a path requires authentication, retrieving the
authorization header, and identifying the current user.
"""
import re
from typing import List, TypeVar
from flask import request


class Auth:
    """Authentication class.

    Provides methods to check if a path requires authentication,
    retrieve the authorization header, and determine the current user.
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determines if a given path requires authentication.

        Args:
            path (str): The path of the request.
            excluded_paths (List[str]): A list of paths that do not require authentication.

        Returns:
            bool: True if the path requires authentication, False otherwise.
        """
        if path is not None and excluded_paths is not None:
            # Check each excluded path for a match with the requested path
            for exclusion_path in map(lambda x: x.strip(), excluded_paths):
                pattern = ''
                if exclusion_path[-1] == '*':
                    # Match paths with wildcard support
                    pattern = '{}.*'.format(exclusion_path[0:-1])
                elif exclusion_path[-1] == '/':
                    # Match paths ending with a slash
                    pattern = '{}/*'.format(exclusion_path[0:-1])
                else:
                    # Match paths as is or with a trailing slash
                    pattern = '{}/*'.format(exclusion_path)
                if re.match(pattern, path):
                    return False  # Path is excluded and does not require authentication
        return True  # Path requires authentication if no match is found

    def authorization_header(self, request=None) -> str:
        """
        Retrieves the Authorization header from the request.

        Args:
            request (flask.Request): The Flask request object.

        Returns:
            str: The value of the Authorization header, or None if not present.
        """
        if request is not None:
            return request.headers.get('Authorization', None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the current user based on the request.

        Args:
            request (flask.Request): The Flask request object.

        Returns:
            User: The current user, or None if not identifiable.
        """
        return None
