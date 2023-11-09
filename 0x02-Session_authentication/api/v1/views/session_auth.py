#!/usr/bin/env python3
"""
flask route for session authentication
"""
from api.v1.views import app_views
from flask import jsonify, request, abort
from models.user import User
from api.v1.app import auth
import os


@app_views.route('/auth_session/login',
                 methods=['POST'],
                 strict_slashes=False)
def create_session():
    """
    create a session for user
    """
    email = request.form.get('email')
    password = request.form.get('password')

    if not email:
        return({"error": "email missing"}), 400

    if not password:
        return jsonify({"error": "password missing"}), 400

    try:
        user = User.search({'email': email})
    except Exception:
        return jsonify({"error": "no user found for this email"}), 404
    if len(user) == 0:
        return jsonify({"error": "no user found for this email"}), 404
    if user[0].is_valid_password(password):
        from api.v1.app import auth
        sessiond_id = auth.create_session(getattr(user[0], 'id'))
        res = jsonify(user[0].to_json())
        res.set_cookie(os.getenv("SESSION_NAME"), sessiond_id)
        return res
    return jsonify({"error": "wrong password"}), 401


@app_views.route('/auth_session/logout',
                 methods=['DELETE'], strict_slashes=False)
def logout():
    """
    logout of session
    """
    if auth.destroy_session(request) is False:
        abort(404)
    return jsonify({}), 200
