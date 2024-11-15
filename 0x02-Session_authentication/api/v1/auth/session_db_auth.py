#!/usr/bin/env python3
"""Session authentication with expiration
and storage support module for the API.

This module extends `SessionExpAuth` to include persistent storage of session
data in a database. It uses the `UserSession` model to store and manage session
details such as session IDs and associated user information.
"""
from flask import request
from datetime import datetime, timedelta

from models.user_session import UserSession
from .session_exp_auth import SessionExpAuth


class SessionDBAuth(SessionExpAuth):
    """Session authentication class with expiration and storage support.

    This class manages user sessions with expiration and persists session
    information in a database using the `UserSession` model.
    """

    def create_session(self, user_id=None) -> str:
        """
        Creates and stores a session ID for a user in the database.

        Parameters:
            - user_id (str): The ID of the user to create a session for.

        Returns:
            - str: The session ID if successfully created, None otherwise.

        Behavior:
            - Stores the session ID and user ID in the database for persistence.
        """
        session_id = super().create_session(user_id)
        if type(session_id) == str:
            kwargs = {
                'user_id': user_id,
                'session_id': session_id,
            }
            user_session = UserSession(**kwargs)
            user_session.save()
            return session_id

    def user_id_for_session_id(self, session_id=None):
        """
        Retrieves the user ID associated with a session ID from the database.

        Parameters:
            - session_id (str): The session ID to look up.

        Returns:
            - str: The user ID if the session is valid, None otherwise.

        Behavior:
            - Checks the session expiration using the `created_at` timestamp
              and the session duration.
            - If the session has expired or is not found, None is returned.
        """
        try:
            sessions = UserSession.search({'session_id': session_id})
        except Exception:
            return None
        if len(sessions) <= 0:
            return None
        cur_time = datetime.now()
        time_span = timedelta(seconds=self.session_duration)
        exp_time = sessions[0].created_at + time_span
        if exp_time < cur_time:
            return None
        return sessions[0].user_id

    def destroy_session(self, request=None) -> bool:
        """
        Destroys an authenticated session by removing it from the database.

        Parameters:
            - request (flask.Request): The HTTP request containing the session cookie.

        Returns:
            - bool: True if the session was successfully destroyed, False otherwise.

        Behavior:
            - Removes the session record from the database using the session ID
              extracted from the request.
            - Returns False if the session does not exist or an error occurs.
        """
        session_id = self.session_cookie(request)
        try:
            sessions = UserSession.search({'session_id': session_id})
        except Exception:
            return False
        if len(sessions) <= 0:
            return False
        sessions[0].remove()
        return True
