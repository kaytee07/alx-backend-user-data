#!/usr/bin/env python3
from flask import Flask, jsonify, request, abort, redirect
from auth import Auth


app = Flask(__name__)
AUTH = Auth()

@app.route("/", methods=["GET"], strict_slashes=False)
def greetings():
    return jsonify({"message": "Bienvenue"})

@app.route("/users", methods=["POST"], strict_slashes=False)
def register_user():
    """
    create new user with email and password from form   
    """
    email = request.form.get('email')
    password = request.form.get('password')
    try:
        user = AUTH.register_user(email, password)
        return jsonify({"email":f"{user.email}",
                         "message": "user created"})
    except ValueError:
        return jsonify({"message":"email already registered"}), 400

@app.route("/sessions", methods=["POST"], strict_slashes=False)
def login():
    """
    create session id and set it as a cookie in response
    """
    email = request.form.get('email')
    password = request.form.get('password')
    validate_user = AUTH.valid_login(email, password)
    if validate_user:
        session_id = AUTH.create_session(email)
        response = jsonify({"email": f"{email}", "message": "logged in"})
        response.set_cookie("session_id", session_id)
        return response
    else:
        abort(401)

@app.route("/sessions", methods=["DELETE"], strict_slashes=False)
def logout():
    """
    find user with session_id and destroy the users session_id
    """
    session_id = request.cookie.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    AUTH.destroy_session(user.id)
    redirect("/")

@app.route("/profile", methods=["GET"], strict_slashes=False)
def profile():
    """
    get user profile
    """
    session_id = request.cookies.get('session_id')
    if session_id is None:
        abort(403)
    user = AUTH.get_user_from_session_id(session_id)
    return jsonify({"email": f"{user.emaila}"}), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
