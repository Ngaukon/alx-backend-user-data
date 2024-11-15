#!/usr/bin/env python3
"""
Module of session authenticating views.

This module provides views for user authentication via session-based
mechanisms, including login and logout endpoints.
"""
import os
from typing import Tuple
from flask import abort, jsonify, request

from models.user import User
from api.v1.views import app_views


@app_views.route('/auth_session/login', methods=['POST'], strict_slashes=False)
def login() -> Tuple[str, int]:
    """
    POST /api/v1/auth_session/login
    Handles user login via session authentication.

    Request form parameters:
        - email (str): The user's email (required).
        - password (str): The user's password (required).

    Return:
        - JSON representation of the authenticated `User` object.
        - Sets a cookie with the session ID upon successful login.
        - 400 if email or password is missing or invalid.
        - 404 if no user is found for the provided email.
        - 401 if the password is incorrect.
    """
    not_found_res = {"error": "no user found for this email"}
    email = request.form.get('email')
    if email is None or len(email.strip()) == 0:
        return jsonify({"error": "email missing"}), 400
    password = request.form.get('password')
    if password is None or len(password.strip()) == 0:
        return jsonify({"error": "password missing"}), 400
    try:
        users = User.search({'email': email})
    except Exception:
        return jsonify(not_found_res), 404
    if len(users) <= 0:
        return jsonify(not_found_res), 404
    if users[0].is_valid_password(password):
        from api.v1.app import auth
        sessiond_id = auth.create_session(getattr(users[0], 'id'))
        res = jsonify(users[0].to_json())
        res.set_cookie(os.getenv("SESSION_NAME"), sessiond_id)
        return res
    return jsonify({"error": "wrong password"}), 401


@app_views.route(
    '/auth_session/logout', methods=['DELETE'], strict_slashes=False)
def logout() -> Tuple[str, int]:
    """
    DELETE /api/v1/auth_session/logout
    Handles user logout by destroying the session.

    Return:
        - An empty JSON object with a 200 status code upon successful logout.
        - 404 if the session cannot be destroyed (e.g., invalid or missing session).
    """
    from api.v1.app import auth
    is_destroyed = auth.destroy_session(request)
    if not is_destroyed:
        abort(404)
    return jsonify({})
