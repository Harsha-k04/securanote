from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required
from securanote.forms import RegisterForm, LoginForm
from securanote.models import User  # Supabase-compatible User
from securanote import mail
from flask_mail import Message
import re
import random
from datetime import datetime, timedelta

# Supabase client
from securanote.supabase_client import supabase

auth_bp = Blueprint('auth', __name__)

# -------------------------------
# Helper functions
# -------------------------------
def send_otp(email, otp):
    msg = Message('Your OTP for Securanote', recipients=[email])
    msg.body = f"Your OTP is: {otp}"
    mail.send(msg)

def is_strong_password(password):
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$'
    return re.match(pattern, password)

def is_risky_login(user_data, request):
    current_ip = request.remote_addr
    return user_data.get("last_ip") and user_data["last_ip"] != current_ip

# -------------------------------
# Routes
# -------------------------------
@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if not is_strong_password(form.password.data):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.', 'error')
            return redirect(url_for('auth.register'))

        # Check if username/email exists
        if supabase.table("users").select("*").eq("username", form.username.data).execute().data:
            flash('Username already exists', 'error')
            return redirect(url_for('auth.register'))
        if supabase.table("users").select("*").eq("email", form.email.data).execute().data:
            flash('Email already registered', 'error')
            return redirect(url_for('auth.register'))

        otp = random.randint(100000, 999999)
        session['pending_user'] = {
            'username': form.username.data,
            'email': form.email.data,
            'password_hash': generate_password_hash(form.password.data)
        }
        session['otp'] = str(otp)
        session['otp_expiry'] = (datetime.utcnow() + timedelta(minutes=5)).timestamp()
        send_otp(form.email.data, otp)
        flash('An OTP has been sent to your email.', 'info')
        return redirect(url_for('auth.verify_otp'))

    return render_template('register.html', form=form)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        # Fetch user from Supabase
        resp = supabase.table("users").select("*").eq("username", form.username.data).execute()
        user_list = resp.get('data') if isinstance(resp, dict) else getattr(resp, 'data', None)

        if not user_list:
            flash('Username not found', 'error')
            return render_template('login.html', form=form)

        user_data = user_list[0]

        # Check password
        if not check_password_hash(user_data.get("password_hash", ""), form.password.data):
            flash('Incorrect password', 'error')
            return render_template('login.html', form=form)

        # Risky login check
        current_ip = request.remote_addr
        if user_data.get("last_ip") and user_data["last_ip"] != current_ip:
            otp = str(random.randint(100000, 999999))
            session['adaptive_user'] = user_data
            session['adaptive_otp'] = otp
            session['adaptive_remember'] = form.remember.data
            session['adaptive_ip'] = current_ip
            session['adaptive_expiry'] = (datetime.utcnow() + timedelta(minutes=5)).timestamp()
            send_otp(user_data["email"], otp)
            flash('Suspicious login detected. OTP sent for verification.', 'info')
            return redirect(url_for('auth.verify_otp'))

        # Normal login
        user = User(str(user_data["id"]), user_data["username"], user_data["email"])
        login_user(user, remember=form.remember.data)

        # Update last login info
        supabase.table("users").update({
            "last_ip": current_ip,
            "last_login_time": datetime.utcnow().isoformat()
        }).eq("id", user_data["id"]).execute()

        flash('Login successful', 'success')
        next_page = request.args.get('next')
        return redirect(next_page or url_for('notes.dashboard'))

    return render_template('login.html', form=form)


@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

# -------------------------------
# OTP routes for registration & adaptive login
# -------------------------------
@auth_bp.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        entered_otp = request.form.get('otp')

        # Registration OTP
        if 'otp' in session:
            if datetime.utcnow().timestamp() > session.get('otp_expiry', 0):
                session.pop('otp', None)
                session.pop('otp_expiry', None)
                flash('OTP expired. Please register again.', 'error')
                return redirect(url_for('auth.register'))

            if entered_otp == session.get('otp'):
                user_data = session.pop('pending_user', None)
                if user_data:
                    supabase.table("users").insert({
                        "username": user_data['username'],
                        "email": user_data['email'],
                        "password_hash": user_data['password_hash'],
                        "is_verified": True,
                        "created_at": datetime.utcnow().isoformat()
                    }).execute()
                    session.pop('otp', None)
                    session.pop('otp_expiry', None)
                    flash('Registration successful. Please log in.', 'success')
                    return redirect(url_for('auth.login'))
            else:
                flash('Invalid OTP', 'error')

        # Adaptive login OTP
        elif 'adaptive_user' in session:
            if datetime.utcnow().timestamp() > session.get('adaptive_expiry', 0):
                flash('OTP expired. Please login again.', 'error')
                return redirect(url_for('auth.login'))

            if entered_otp == session.get('adaptive_otp'):
                user_data = session.pop('adaptive_user')
                user = User(user_data["id"], user_data["username"], user_data["email"])
                login_user(user, remember=session.pop('adaptive_remember', False))
                supabase.table("users").update({
                    "last_ip": session.pop('adaptive_ip'),
                    "last_login_time": datetime.utcnow().isoformat()
                }).eq("id", user_data["id"]).execute()
                session.pop('adaptive_otp', None)
                session.pop('adaptive_expiry', None)
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
    
@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        # Optional: check if email exists in Supabase
        session['reset_email'] = email
        otp = str(random.randint(100000, 999999))
        session['reset_otp'] = otp
        send_otp(email, otp)
        flash("OTP sent to your email for password reset.", "info")
        return redirect(url_for('auth.verify_reset_otp'))
    return render_template('forgot_password.html')
