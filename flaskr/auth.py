from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, current_user
import functools
import bcrypt
from flask import (
    Blueprint, request, jsonify
)
from flaskr.db import get_db
from datetime import timedelta

jwt = JWTManager()
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def verify_password(stored_password, provided_password):
    return bcrypt.checkpw(provided_password.encode('utf-8'), stored_password.encode('utf-8'))


bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/register', methods=['POST'])
def register():
    username = request.json.get('username', None)
    email = request.json.get('email', None)
    password = request.json.get('password', None)
    if not username or not password or not email:
        return jsonify({"error": "Missing username or password"}), 400
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id FROM user WHERE username = ? OR email = ?", (username, email))
    if cursor.fetchone() is not None:
        return jsonify({"error": "Username already taken"}), 409

    hashed_password = hash_password(password)
    cursor.execute("INSERT INTO user (username,email, password) VALUES (?, ?,?)", (username,email, hashed_password))
    db.commit()
    user_id = cursor.lastrowid
    access_token = create_access_token(identity=user_id,expires_delta=timedelta(minutes=60))

    return jsonify(username = username, email=email, access_token=access_token, message= "User created successfully"), 201


@bp.route('/login', methods=['POST'])
def login():
    username = request.json.get('username', None)
    password = request.json.get('password', None)
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 400

    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT id, password FROM user WHERE username = ?", (username,))
    user = cursor.fetchone()
    if user is None:
        return jsonify({"error": "Incorrect username"}), 401

    if not verify_password(user['password'], password):
        return jsonify({"error": "Incorrect password"}), 401

    print(cursor)

    access_token = create_access_token(identity=cursor.lastrowid,expires_delta=timedelta(minutes=60))
    return jsonify(access_token=access_token), 200

@bp.route('/getMe', methods=['GET'])
@jwt_required()
def protected():
    return jsonify(
        id=current_user['id'],
        username=current_user['username'],
        email=current_user['email'],
    )


@jwt.user_identity_loader
def user_identity_lookup(user):
    print(user)
    return user

@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    cursor = get_db().cursor()
    cursor.execute("SELECT * FROM user WHERE id = ?", (identity,))
    user = cursor.fetchone()
    return user

def init_jwt(app):
    jwt.init_app(app)

