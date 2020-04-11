from marshmallow import Schema, fields, post_load, validate
from chatapp.models import User
from chatapp import bcrypt

class UserSchema(Schema):
    public_id = fields.UUID()
    username = fields.Str(required=True, validate=validate.Length(max=15))
    email = fields.Email(required=True)
    password = fields.Str(required=True)
    profile_picture = fields.Str()

    @post_load
    def make_user(self, data, **kwargs):
        if 'password' in data:
            unhashed = data['password']
            data['password'] = bcrypt.generate_password_hash(unhashed)
        return User(**data)