#!/usr/bin/env python3
"""
Module of Index views.

This module defines several routes to provide API status, statistics,
and simulate error scenarios for unauthorized and forbidden access.
"""
from flask import jsonify, abort
from api.v1.views import app_views


@app_views.route('/status', methods=['GET'], strict_slashes=False)
def status() -> str:
    """
    GET /api/v1/status
    Returns the status of the API.

    Return:
        - JSON response with the status of the API.
    """
    return jsonify({"status": "OK"})


@app_views.route('/stats/', strict_slashes=False)
def stats() -> str:
    """
    GET /api/v1/stats
    Returns the count of each object type in the database.

    Return:
        - JSON response containing the number of objects.
    """
    from models.user import User  # Importing User model dynamically
    stats = {}
    stats['users'] = User.count()  # Get the count of User objects
    return jsonify(stats)


@app_views.route('/unauthorized/', strict_slashes=False)
def unauthorized() -> None:
    """
    GET /api/v1/unauthorized
    Simulates an unauthorized error (401).

    Return:
        - Aborts the request with a 401 Unauthorized error.
    """
    abort(401)


@app_views.route('/forbidden/', strict_slashes=False)
def forbidden() -> None:
    """
    GET /api/v1/forbidden
    Simulates a forbidden error (403).

    Return:
        - Aborts the request with a 403 Forbidden error.
    """
    abort(403)
