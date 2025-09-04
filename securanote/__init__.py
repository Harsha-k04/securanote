from flask import Flask
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
from datetime import timedelta
import pytz
import os
from securanote.supabase_client import supabase  # your Supabase client

login_manager = LoginManager()
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
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = 'securanote@gmail.com'
    app.config['MAIL_PASSWORD'] = 'nyyq xzom ptoy fgjv'
    app.config['MAIL_DEFAULT_SENDER'] = 'securanote@gmail.com'
    app.config['REMEMBER_COOKIE_DURATION'] = timedelta(days=7)
    app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')

    mail.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'
    limiter.init_app(app)

    from securanote.routes.auth import auth_bp
    app.register_blueprint(auth_bp)

    from securanote.routes.notes import notes_bp
    app.register_blueprint(notes_bp)

    from securanote.routes.ai_routes import ai_bp
    app.register_blueprint(ai_bp)

    @app.template_filter('localtime')
    def localtime_filter(utc_dt):
        if utc_dt is None:
            return ""
        ist = pytz.timezone('Asia/Kolkata')
        return utc_dt.replace(tzinfo=pytz.utc).astimezone(ist).strftime('%Y-%m-%d %I:%M %p')

    return app

# -------------------------------
# Flask-Login user loader (Supabase version)
# -------------------------------
@login_manager.user_loader
def load_user(user_id):
    from flask_login import UserMixin

    # Fetch user from Supabase
    resp = supabase.table("users").select("*").eq("id", int(user_id)).execute()
    if resp.data:
        user_data = resp.data[0]
        class SupabaseUser(UserMixin):
            id = user_data["id"]
            username = user_data["username"]
            email = user_data["email"]
        return SupabaseUser()
    return None
