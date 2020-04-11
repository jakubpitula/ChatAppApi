from flask import Blueprint, request, jsonify, make_response, current_app
from chatapp.models import User, db
from chatapp.schemas import UserSchema
from marshmallow import ValidationError
from chatapp.users.utils import token_required
from chatapp import bcrypt
import uuid
import jwt
import datetime

users = Blueprint('users', __name__)

user_schema = UserSchema()
users_schema = UserSchema(many=True)


#Login

@users.route('/login')
def login():
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(username=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if bcrypt.check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id,
         'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=60)}, current_app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

#  User CRUD

@users.route('/user', methods=['GET'])
def get_all_users():
    users = User.query.all()
    result = users_schema.dump(users)

    return jsonify(result)

@users.route('/user/<public_id>', methods=['GET'])
def get_single_user(public_id):
    user = User.query.filter_by(public_id=public_id).first()
    if not user:
        return jsonify({"errors" : "User not found"}), 400

    result = user_schema.dump(user)
    return result

@users.route('/user', methods=['POST'])
def create_user():
    data = request.json
    try:
        user = user_schema.load(data)
    except ValidationError as err:
        return jsonify({"errors" : err.messages}), 422

    if User.query.filter_by(email=user.email).first():
        return jsonify({"errors" : "Email already exists."}), 400
    elif User.query.filter_by(username=user.username).first():
        return jsonify({"errors" : "Username already exists."}), 400
    else:
        user.public_id = str(uuid.uuid4())
        db.session.add(user)
        db.session.commit()
        result = user_schema.dump(user)
        return result, 201
        
@users.route('/user/<public_id>', methods=['PUT'])
@token_required
def update_user(current_user, public_id):

    data = request.json
    tmp_user = User.query.filter_by(public_id=public_id, id=current_user.id).first()
    if not tmp_user:
        return jsonify({"errors" : "User not found"}), 400

    if 'email' in data:
        tmp_user.email = data['email']
    if 'name' in data:
        tmp_user.username = data['username']
    try:
        tmp_user_loaded = user_schema.load(data, partial=True)
    except ValidationError as err:
        return jsonify({"errors" : err.messages}), 422

    if 'email' in data and User.query.filter(User.email==data['email'], User.public_id!=public_id).first():
        return jsonify({"errors" : "Email already exists."}), 400
    elif 'username' in data and User.query.filter(User.username==data['username'], User.public_id!=public_id).first():
        return jsonify({"errors" : "Username already exists."}), 400
    else:
        user = User.query.filter_by(public_id=public_id).first()

        if 'password' in data:
            user.password = bcrypt.generate_password_hash(data['password'])
        if 'email' in data:
            user.email = data['email']
        if 'username' in data:
            user.username = data['username']
        if 'profile_picture' in data:
            user.profile_picture = data['profile_picture']

        db.session.commit()
        result = user_schema.dump(user)
        return result

@users.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    user = User.query.filter_by(public_id=public_id, id=current_user.id).first()
    if not user:
        return jsonify({"errors" : "User not found"}), 400

    db.session.delete(user)
    db.session.commit()

    return jsonify({"message" : "User deleted"})