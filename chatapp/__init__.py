from flask import Flask
from chatapp.config import Config
from chatapp.models import db
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(Config)

    bcrypt.init_app(app)
    db.init_app(app)
    with app.app_context():
        db.create_all()

    from chatapp.users.routes import users

    app.register_blueprint(users)

    return app