#!/usr/bin/env python3
"""Session authentication with expiration module for the API.

This module extends the `SessionAuth` class to include session expiration functionality,
allowing sessions to expire after a configurable duration.
"""
import os
from flask import request
from datetime import datetime, timedelta

from .session_auth import SessionAuth


class SessionExpAuth(SessionAuth):
    """Session authentication class with expiration.

    This class manages user sessions with an added feature of expiration.
    Sessions can be configured to expire after a specified duration.
    """

    def __init__(self) -> None:
        """
        Initializes a new SessionExpAuth instance.

        Attributes:
            - session_duration (int): The duration (in seconds) for which a session is valid.
              Defaults to 0, indicating no expiration.
        """
        super().__init__()
        try:
            self.session_duration = int(os.getenv('SESSION_DURATION', '0'))
        except Exception:
            self.session_duration = 0

    def create_session(self, user_id=None):
        """
        Creates a session ID for a user and stores the session details.

        Parameters:
            - user_id (str): The ID of the user to create a session for.

        Returns:
            - str: The session ID if successfully created, None otherwise.

        Session details include:
            - user_id: The associated user's ID.
            - created_at: The timestamp when the session was created.
        """
        session_id = super().create_session(user_id)
        if type(session_id) != str:
            return None
        self.user_id_by_session_id[session_id] = {
            'user_id': user_id,
            'created_at': datetime.now(),
        }
        return session_id

    def user_id_for_session_id(self, session_id=None) -> str:
        """
        Retrieves the user ID associated with a given session ID, considering expiration.

        Parameters:
            - session_id (str): The session ID to look up.

        Returns:
            - str: The user ID if the session is valid, None otherwise.

        Behavior:
            - If session_duration is 0 or less, the session does not expire.
            - If the session has expired, None is returned.
        """
        if session_id in self.user_id_by_session_id:
            session_dict = self.user_id_by_session_id[session_id]
            if self.session_duration <= 0:
                return session_dict['user_id']
            if 'created_at' not in session_dict:
                return None
            cur_time = datetime.now()
            time_span = timedelta(seconds=self.session_duration)
            exp_time = session_dict['created_at'] + time_span
            if exp_time < cur_time:
                return None
            return session_dict['user_id']

