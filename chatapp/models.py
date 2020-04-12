from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), nullable=False, unique=True)
    email = db.Column(db.String(80), nullable=False, unique=True)
    password = db.Column(db.String(60), nullable=False)
    profile_picture = db.Column(db.String())
    public_id = db.Column(db.String(50), nullable=False, unique=True)
    admin = db.Column(db.Boolean, nullable=False)