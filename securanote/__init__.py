from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime
import pytz
import os
from flask_mail import Mail
from flask_mail import Message
from datetime import timedelta

db = SQLAlchemy()
login_manager = LoginManager()
migrate = Migrate()
mail = Mail()
limiter = Limiter(get_remote_address)
def send_otp(recipient_email, otp):
    msg = Message('Your OTP Code',
                  recipients=[recipient_email])
    msg.body = f'Your OTP is: {otp}'
    mail.send(msg)

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'securanote-super-secret-key')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI')
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'harsha332004@gmail.com' # your email
    app.config['MAIL_PASSWORD'] = 'mjnk wgzh skrb bmsx'  # app password
    app.config['MAIL_DEFAULT_SENDER'] = 'your_email@example.com'
    app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=7)
    app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')

    mail.init_app(app)
    db.init_app(app)
    from securanote import models
    migrate.init_app(app, db)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'
    limiter.init_app(app)
    

    from securanote.routes.auth import auth_bp
    app.register_blueprint(auth_bp)

    from securanote.routes.notes import notes_bp
    app.register_blueprint(notes_bp)

    @app.template_filter('localtime')
    def localtime_filter(utc_dt):
        if utc_dt is None:
            return ""
        ist = pytz.timezone('Asia/Kolkata')
        return utc_dt.replace(tzinfo=pytz.utc).astimezone(ist).strftime('%Y-%m-%d %I:%M %p')

    return app

@login_manager.user_loader
def load_user(user_id):
    from securanote.models import User
    return User.query.get(int(user_id))
