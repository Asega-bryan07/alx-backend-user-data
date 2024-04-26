#!/usr.bin/env python3
'''
will define a _hash_password method that takes in a password
string arguments and returns bytes.
The returned bytes is a salted hash of the input password,
hashed with bcrypt.hashpw
implement the Auth.register_user in the Auth class
Auth._db is a private property and should NEVER be used
from outside the class.
Auth.register_user should take mandatory email and password
string arguments and return a User object.
If a user already exist with the passed email, raise a ValueError
with the message User <user's email> already exists.
If not, hash the password with _hash_password, save the user to the
database using self._db and return the User object.
'''


import bcrypt
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4

from typing import Union


def _hash_password(password: str) -> str:
    '''
    method that takes in a password
    string arguments and returns bytes.
    The returned bytes is a salted hash of the input password,
    hashed with bcrypt.hashpw
    '''
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def _generate_uuid() -> str:
    '''
    generate the uuid
    '''
    id = uuid4()
    return str(id)


class Auth:
    '''
    Auth class that interacts with the authentication database
    '''
    def __init__(self):
        '''
        _summary_
        '''
        self._db = DB()

    def register_user(self, email: str, password: str) -> Union[None, User]:
        '''
        _summary_
        '''
        try:
            # find a user with a given email
            self._db.find_user_by(email=email)
        except NoResultFound:
            # Add a user to the database
            return self._db.add_user(email, _hash_password(password))

        else:
            # if user already exists, throw an error
            raise ValueError('User {} already exists'.format(email))

    def valid_login(self, email: str, password: str) -> bool:
        '''
        email - str
            password - str
            returns boolean: Logged in, or invalid credentials
        '''
        try:
            # find a user with a given email
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return False
        # check password validity
        return bcrypt.checkpw(password.encode('utf-8'), user.hashed_password)

    def create_session(self, email: str) -> str:
        '''
        email - str
        _description_
        returns: str _description_
        '''
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None
        else:
            user.session_id = _generate_uuid()
        return user.session_id

    def get_user_from_session_id(self, session_id: str) -> User:
        '''
        _summary_
        Args:.Session_id (_type_): _description_
        '''
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        else:
            return User

    def destroy_session(self, user_id: str) -> None:
        '''
        Args:
        user_id (str): _description_
        '''
        try:
            user._db.find_user_by(id=user_id)
        except NoResultFound:
            return None
        else:
            user.session_id = None
        return None

    def get_reset_password_token(self, email: str) -> str:
        '''
        Args:
        email (str): _description_
        '''
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError
        else:
            user.reset_token = _generate_uuid()
        return user.reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        '''
        Args:
        reset_token: str _description_
        password: str _description_
        '''
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError
        else:
            user.hashed_password = _hash_password(password)
        user.reset_token = None
        return None
