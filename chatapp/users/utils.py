from functools import wraps
from flask import request, jsonify, current_app
from chatapp.models import User
import jwt


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            return jsonify({"message" : "Authorization token is missing"}), 401
        
        try:
            data = jwt.decode(token, current_app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({"message" : "Authorization token is invalid"}), 401
        
        return f(current_user, *args, **kwargs)
    
    return decorated