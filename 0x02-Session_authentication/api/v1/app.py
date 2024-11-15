#!/usr/bin/env python3
"""
Route module for the API.

This module initializes the Flask application, sets up routes, handles
error responses, and manages user authentication using various methods.
"""
import os
from os import getenv
from flask import Flask, jsonify, abort, request
from flask_cors import (CORS, cross_origin)

from api.v1.views import app_views
from api.v1.auth.auth import Auth
from api.v1.auth.basic_auth import BasicAuth
from api.v1.auth.session_auth import SessionAuth
from api.v1.auth.session_db_auth import SessionDBAuth
from api.v1.auth.session_exp_auth import SessionExpAuth

# Initialize the Flask application
app = Flask(__name__)

# Register the blueprint containing the views
app.register_blueprint(app_views)

# Enable Cross-Origin Resource Sharing (CORS) for API routes
CORS(app, resources={r"/api/v1/*": {"origins": "*"}})

# Set up authentication based on the AUTH_TYPE environment variable
auth = None
auth_type = getenv('AUTH_TYPE', 'auth')
if auth_type == 'auth':
    auth = Auth()  # Default authentication
if auth_type == 'basic_auth':
    auth = BasicAuth()  # Basic authentication
if auth_type == 'session_auth':
    auth = SessionAuth()  # Session-based authentication
if auth_type == 'session_exp_auth':
    auth = SessionExpAuth()  # Session-based authentication with expiration
if auth_type == 'session_db_auth':
    auth = SessionDBAuth()  # Session-based authentication with database storage


@app.errorhandler(404)
def not_found(error) -> str:
    """
    Handle 404 Not Found errors.

    Returns:
        - JSON response with an error message and a 404 status code.
    """
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(401)
def unauthorized(error) -> str:
    """
    Handle 401 Unauthorized errors.

    Returns:
        - JSON response with an error message and a 401 status code.
    """
    return jsonify({"error": "Unauthorized"}), 401


@app.errorhandler(403)
def forbidden(error) -> str:
    """
    Handle 403 Forbidden errors.

    Returns:
        - JSON response with an error message and a 403 status code.
    """
    return jsonify({"error": "Forbidden"}), 403


@app.before_request
def authenticate_user():
    """
    Authenticate a user before processing a request.

    This function is executed before each request to determine if the user
    is authenticated. If authentication is required:
    - Checks for an authorization header or session cookie.
    - Retrieves the user object using the appropriate authentication method.

    If no valid credentials are provided, it aborts the request with a 401 error.
    If the user is not authorized, it aborts the request with a 403 error.
    """
    if auth:
        # Paths excluded from authentication
        excluded_paths = [
            "/api/v1/status/",  # Status check endpoint
            "/api/v1/unauthorized/",  # Simulates unauthorized access
            "/api/v1/forbidden/",  # Simulates forbidden access
            "/api/v1/auth_session/login/",  # Login endpoint
        ]
        if auth.require_auth(request.path, excluded_paths):
            # Retrieve the current user
            user = auth.current_user(request)
            if auth.authorization_header(request) is None and \
                    auth.session_cookie(request) is None:
                # No credentials provided
                abort(401)
            if user is None:
                # User is not authorized
                abort(403)
            # Attach the user object to the request for further use
            request.current_user = user


if __name__ == "__main__":
    # Get host and port from environment variables with defaults
    host = getenv("API_HOST", "0.0.0.0")
    port = getenv("API_PORT", "5000")
    # Start the Flask application
    app.run(host=host, port=port)
