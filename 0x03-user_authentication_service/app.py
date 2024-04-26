#!/usr/bin/env python3
'''
set up a basic Flask app.
Create a Flask app that has a single GET route ("/")
and use flask.jsonify to return a JSON payload of the form:
{"message": "Bienvenue"}
'''


from flask import Flask, jsonify, request, abort, redirect
from auth import Auth

AUTH = Auth()

app = Flask(__name__)


@app.route('/', methods=['GET'])
def index() -> str:
    '''
    Flask app that has a single GET route ("/")
    '''
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'])
def users() -> str:
    '''
    implement the end-point to register a user
    '''
    email = request.form.get('email')
    password = request.form.get('password')

    # register a user if does not exist
    try:
        user = AUTH.register_user(email, password)
        return jsonify({"email": user.email, "message": "user created"})
    except Exception:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'])
def login() -> str:
    '''
    _summary_
    Returns:
        str: _description
    '''
    email = request.form.get('email')
    password = request.form.get('password')

    if not (AUTH.valid_login(email, password)):
        abort(401)
    else:
        # create new session
        session_id = AUTH.create_session(email)
        response = jsonify({"email": email, "message": "logged in"})
        response.set_cookie('session_id', session_id)

        return response


@app.route('/sessions', methods=['DELETE'])
def logout() -> str:
    '''
        _summary_
            Returns:
                        str: _description
    '''
    session_id = request.cookies.get('session_id')
    if not user:
        abort(403)
        AUTH.destroy_session(user.id)
        return redirect('/')


@app.route('/reset_password', methods=['POST'])
def get_reset_password_token() -> str:
    '''
    _summary_
    Returns:
        str: _description
    '''
    email = request.form.get('email')
    try:
        reset_token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": reset_token}), 200
    except Exception:
        abort(403)


@app.route('/reset_password', methods=['PUT'])
def update_password() -> str:
    '''
    _summary_
        Returns:
        str: _description
    '''
    email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    new_password = request.form.get('new_password')
    try:
        AUTH.update_password(reset_token, new_password)
        return jsonify({"email": email, "message": "Password updated"}), 200
    except Exception:
        abort(403)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
