#!/usr/bin/env python3
"""
Authentication module for the API.

This module provides the base `Auth` class for implementing various
authentication mechanisms, including methods to handle authentication
requirements, retrieve authorization headers, manage session cookies, and
determine the current user.
"""
import os
import re
from typing import List, TypeVar
from flask import request


class Auth:
    """Authentication class.

    This base class defines common authentication behaviors that can be extended
    by other classes to implement specific authentication mechanisms.
    """
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determines if a given path requires authentication.

        Parameters:
            - path (str): The path to check.
            - excluded_paths (List[str]): A list of paths that do not require authentication.

        Returns:
            - bool: True if the path requires authentication, False otherwise.
        
        Note:
            - Paths ending with `*` will match any subpath.
            - A trailing `/` will match paths without further subpaths.
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

    def authorization_header(self, request=None) -> str:
        """
        Retrieves the `Authorization` header from the request.

        Parameters:
            - request: The Flask request object.

        Returns:
            - str: The value of the `Authorization` header if present, None otherwise.
        """
        if request is not None:
            return request.headers.get('Authorization', None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieves the current user from the request.

        Parameters:
            - request: The Flask request object.

        Returns:
            - User: Always returns None. Should be implemented in subclasses.
        """
        return None

    def session_cookie(self, request=None) -> str:
        """
        Retrieves the session cookie value from the request.

        Parameters:
            - request: The Flask request object.

        Returns:
            - str: The value of the session cookie if present, None otherwise.
        """
        if request is not None:
            cookie_name = os.getenv('SESSION_NAME')
            return request.cookies.get(cookie_name)
