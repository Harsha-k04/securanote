from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user
from securanote.forms import RegisterForm, LoginForm
from securanote.models import User, Note
from securanote import db
import re
import random
from flask_mail import Message
from securanote import mail
from datetime import datetime, timedelta

auth_bp = Blueprint('auth', __name__)

def send_otp(email, otp):
    msg = Message('Your OTP for Securanote', recipients=[email])
    msg.body = f"Your OTP is: {otp}"
    mail.send(msg)
def is_strong_password(password):
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$'
    return re.match(pattern, password)
def is_risky_login(user, request):
    # Check for new IP login as risk (you can add more conditions)
    current_ip = request.remote_addr
    if user.last_ip and user.last_ip != current_ip:
        return True
    return False

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if not is_strong_password(form.password.data):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.', 'error')
            return redirect(url_for('auth.register'))

        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists', 'error')
            return redirect(url_for('auth.register'))

        if User.query.filter_by(email=form.email.data).first():
            flash('Email already registered', 'error')
            return redirect(url_for('auth.register'))

        otp = random.randint(100000, 999999)
        session['pending_user'] = {
            'username': form.username.data,
            'email': form.email.data,
            'password': generate_password_hash(form.password.data)
        }
        session['otp'] = str(otp)
        session['otp_expiry'] = (datetime.utcnow() + timedelta(minutes=5)).timestamp()

        send_otp(form.email.data, otp)
        flash('An OTP has been sent to your email.', 'info')
        return redirect(url_for('auth.verify_otp'))

    return render_template('register.html', form=form)


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    session.pop('_flashes', None)
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None:
            flash('Username not found', 'error')
        elif not check_password_hash(user.password_hash, form.password.data):
            flash('Incorrect password', 'error')
        else:
            if is_risky_login(user, request):
                otp = str(random.randint(100000, 999999))
                session['adaptive_user_id'] = user.id
                session['adaptive_otp'] = otp
                session['adaptive_remember'] = form.remember.data
                session['adaptive_ip'] = request.remote_addr
                session['adaptive_expiry'] = (datetime.utcnow() + timedelta(minutes=5)).timestamp()
                send_otp(user.email, otp)
                flash('Suspicious login detected. OTP sent for verification.', 'info')
                return redirect(url_for('auth.verify_otp'))

            login_user(user, remember=form.remember.data)
            user.last_ip = request.remote_addr
            user.last_login_time = datetime.utcnow()
            db.session.commit()
            flash('Login successful', 'success')
            next_page = request.args.get('next')
            return redirect(next_page or url_for('notes.dashboard'))
    return render_template('login.html', form=form)

@auth_bp.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()

        if user:
            otp = str(random.randint(100000, 999999))
            session['reset_email'] = email
            session['reset_otp'] = otp
            send_otp(email, otp)
            flash('An OTP has been sent to your email.', 'info')
            return redirect(url_for('auth.verify_reset_otp'))
        else:
            flash('No account found with that email.', 'error')

    return render_template('forgot_password.html')

@auth_bp.route('/verify_reset_otp', methods=['GET', 'POST'])
def verify_reset_otp():
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        if entered_otp == session.get('reset_otp'):
            flash('OTP verified. You can now reset your password.', 'success')
            return redirect(url_for('auth.reset_password'))
        else:
            flash('Incorrect OTP.', 'error')

    return render_template('verify_reset_otp.html')

@auth_bp.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        new_password = request.form.get('new_password')
        email = session.get('reset_email')

        if not is_strong_password(new_password):
            flash('Password must be at least 8 characters and include uppercase, lowercase, number, and special character.', 'error')
            return redirect(url_for('auth.reset_password'))

        if email:
            user = User.query.filter_by(email=email).first()
            if user:
                user.password_hash = generate_password_hash(new_password)
                db.session.commit()
                session.pop('reset_email', None)
                session.pop('reset_otp', None)
                flash('Password reset successful. Please log in.', 'success')
                return redirect(url_for('auth.login'))

        flash('Session expired or invalid.', 'error')

    return render_template('reset_password.html')


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear() 
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form.get('otp')
        
        # Handle registration OTP
        if 'otp' in session:
            expiry = session.get('otp_expiry')
            if expiry and datetime.utcnow().timestamp() > expiry:
                session.pop('otp', None)
                session.pop('otp_expiry', None)
                flash('OTP has expired. Please register again.', 'error')
                return redirect(url_for('auth.register'))

            if entered_otp == session.get('otp'):
                user_data = session.get('pending_user')
                if user_data:
                    new_user = User(
                        username=user_data['username'],
                        email=user_data['email'],
                        password_hash=user_data['password'],
                        is_verified=True
                    )
                    db.session.add(new_user)
                    db.session.commit()
                    session.pop('pending_user', None)
                    session.pop('otp', None)
                    session.pop('otp_expiry', None)
                    flash('Registration successful. Please log in.', 'success')
                    return redirect(url_for('auth.login'))
            else:
                flash('Invalid OTP', 'error')
        
        # Handle adaptive login OTP
        elif 'adaptive_user_id' in session:
            expiry = session.get('adaptive_expiry')
            if expiry and datetime.utcnow().timestamp() > expiry:
                flash('OTP expired. Please login again.', 'error')
                return redirect(url_for('auth.login'))

            if entered_otp == session.get('adaptive_otp'):
                user = User.query.get(session['adaptive_user_id'])
                if user:
                    login_user(user, remember=session.get('adaptive_remember', False))
                    user.last_ip = session.get('adaptive_ip')
                    user.last_login_time = datetime.utcnow()
                    db.session.commit()
                    session.pop('adaptive_user_id', None)
                    session.pop('adaptive_otp', None)
                    session.pop('adaptive_remember', None)
                    session.pop('adaptive_expiry', None)
                    session.pop('adaptive_ip', None)
                    flash('Login verified with OTP.', 'success')
                    return redirect(url_for('notes.dashboard'))
            else:
                flash('Invalid OTP', 'error')

    return render_template('verify_otp.html')

@auth_bp.route('/resend_otp', methods=['POST'])
def resend_otp():
    user_data = session.get('pending_user')
    if not user_data:
        flash('No pending registration found.', 'error')
        return redirect(url_for('auth.register'))

    otp = random.randint(100000, 999999)
    session['otp'] = str(otp)
    session['otp_expiry'] = (datetime.utcnow() + timedelta(minutes=5)).timestamp()
    
    send_otp(user_data['email'], otp)
    flash('A new OTP has been sent to your email.', 'info')
    return redirect(url_for('auth.verify_otp'))

@auth_bp.route('/resend_reset_otp', methods=['POST'])
def resend_reset_otp():
    email = session.get('reset_email')
    if not email:
        flash('Session expired or email not found.', 'error')
        return redirect(url_for('auth.forgot_password'))

    otp = str(random.randint(100000, 999999))
    session['reset_otp'] = otp
    send_otp(email, otp)
    flash('OTP resent successfully.', 'info')
    return redirect(url_for('auth.verify_reset_otp'))


