from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, session, current_app, send_file
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
from securanote import db
from securanote.models import Note
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
import os
import io
from PIL import Image
import uuid
import base64
import mimetypes
import random
import smtplib
from email.message import EmailMessage
import qrcode

# UTILITIES
from securanote.utils import (
    encrypt_blowfish, decrypt_blowfish,
    encrypt_blowfish_bytes, decrypt_blowfish_bytes,
    blowfish_key,
    encrypt_chacha, decrypt_chacha, decrypt_chacha_bytes,
    upload_file_to_s3, download_file_from_s3,
    fernet
)

# Load env
load_dotenv()

notes_bp = Blueprint('notes', __name__)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp3', 'mp4', 'pdf'}

UPLOAD_FOLDER = os.path.join('static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ------------------------ Dashboard ------------------------
@notes_bp.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        encryption_type = request.form.get('encryption_type')
        pin = request.form.get('pin')

        if not pin or len(pin) < 4:
            flash('PIN must be at least 4 digits.', 'error')
            return redirect(url_for('notes.dashboard'))

        # Encrypt content
        try:
            if encryption_type == 'AES':
                encrypted_content = fernet.encrypt(content.encode()).decode()
            elif encryption_type == 'ChaCha':
                encrypted_content = encrypt_chacha(content.encode())
            elif encryption_type == 'Blowfish':
                encrypted_content = encrypt_blowfish(content.encode(), blowfish_key)
            else:
                flash('Invalid encryption type selected.', 'error')
                return redirect(url_for('notes.dashboard'))
        except Exception as e:
            flash(f"Content encryption failed: {e}", "error")
            return redirect(url_for('notes.dashboard'))

        pin_hash = generate_password_hash(pin)

        file = request.files.get('file')
        filename = None
        encrypted_file_data = None

        if file and file.filename != '' and allowed_file(file.filename):
            filename = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
            file_data = file.read()
            try:
                if encryption_type == 'AES':
                    encrypted_file_data = fernet.encrypt(file_data)
                elif encryption_type == 'ChaCha':
                    encrypted_file_data = encrypt_chacha(file_data)
                    if isinstance(encrypted_file_data, str):
                        encrypted_file_data = encrypted_file_data.encode()
                elif encryption_type == 'Blowfish':
                    encrypted_file_data = encrypt_blowfish_bytes(file_data, blowfish_key)
            except Exception as e:
                flash(f"File encryption failed: {e}", 'error')
                return redirect(url_for('notes.dashboard'))

            upload_success = upload_file_to_s3(encrypted_file_data, filename)
            if not upload_success:
                flash("Failed to upload encrypted file to cloud.", "error")
                return redirect(url_for("notes.dashboard"))

        new_note = Note(
            title=title,
            encrypted_content=encrypted_content,
            encryption_type=encryption_type,
            user_id=current_user.id,
            timestamp=datetime.utcnow(),
            pin_hash=pin_hash,
            file_path=filename,
            file_data=encrypted_file_data
        )

        if request.form.get("share_note") == "yes":
            new_note.share_token = uuid.uuid4().hex
            new_note.views_left = 1  # View once only
            new_note.share_expiry = None

        db.session.add(new_note)
        db.session.commit()
        flash('Note added successfully.', 'success')
        return redirect(url_for('notes.dashboard'))

    user_notes = Note.query.filter_by(user_id=current_user.id).order_by(Note.timestamp.desc()).all()
    return render_template('dashboard.html', notes=user_notes, user=current_user)

# ------------------------ View Note ------------------------
@notes_bp.route("/note/<int:note_id>/view", methods=["GET", "POST"])
@login_required
def view_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.user_id != current_user.id:
        abort(403)

    file_url = None
    file_ext = None
    decrypted = None
    share_link = None
    qr_image_url = None
    qr_code_base64 = None
    decrypted_path = None

    attempt_key = f"attempts_note_{note_id}"
    session.setdefault(attempt_key, 0)

    if request.method == "POST":
        if "pin" in request.form:
            entered_pin = request.form["pin"]
            if check_password_hash(note.pin_hash, entered_pin):
                session[f"pin_used_{note_id}"] = entered_pin
                session.pop(f"pin_attempts_{note_id}", None)
            else:
                attempts = session.get(f"pin_attempts_{note_id}", 0) + 1
                session[f"pin_attempts_{note_id}"] = attempts
                if attempts >= 3:
                    session.pop(f"pin_attempts_{note_id}", None)
                    return redirect(url_for("notes.verify_email_for_reset", note_id=note_id))
                flash("Incorrect PIN", "danger")
                return render_template("enter_pin.html", note=note, attempts=session[attempt_key])

        elif "generate_link" in request.form:
            view_once = request.form.get("view_once") == "on"
            note.share_token = uuid.uuid4().hex
            note.views_left = 1 if view_once else None
            db.session.commit()
            share_link = url_for("notes.shared_note", token=note.share_token, _external=True)
            qr = qrcode.make(share_link)
            filename = f"{note.id}_qr.png"
            temp_folder = os.path.join(current_app.root_path, 'static', 'temp')
            os.makedirs(temp_folder, exist_ok=True)
            qr_path = os.path.join(temp_folder, filename)
            qr.save(qr_path)
            qr_image_url = url_for('static', filename=f'temp/{filename}', _external=True)
            buf = io.BytesIO()
            qr.save(buf, format='PNG')
            qr_code_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    if request.method == "GET":
        return render_template("enter_pin.html", note=note, attempts=session[attempt_key])

    # Decrypt note content
    try:
        if note.encryption_type == 'AES':
            decrypted = fernet.decrypt(note.encrypted_content.encode()).decode()
        elif note.encryption_type == 'ChaCha':
            decrypted = decrypt_chacha(note.encrypted_content)
        elif note.encryption_type == 'Blowfish':
            decrypted = decrypt_blowfish(note.encrypted_content, blowfish_key)
        else:
            flash("Unsupported encryption type.", "danger")
            return render_template("enter_pin.html", note=note)
    except Exception as e:
        flash(f"Decryption failed: {e}", "danger")
        return render_template("enter_pin.html", note=note)

    # Decrypt file if exists
    if note.file_path:
        file_ext = note.file_path.rsplit('.', 1)[-1].lower()
        encrypted_file_path = os.path.join(current_app.root_path, 'static', 'uploads', note.file_path)
        try:
            encrypted_data = download_file_from_s3(note.file_path)
            if not encrypted_data:
                flash("Could not fetch encrypted file from cloud.", "danger")
                return redirect(url_for("notes.view_note", note_id=note.id))

            if note.encryption_type == 'AES':
                decrypted_data = fernet.decrypt(encrypted_data)
            elif note.encryption_type == 'ChaCha':
                decrypted_data = decrypt_chacha_bytes(encrypted_data)
            elif note.encryption_type == 'Blowfish':
                decrypted_data = decrypt_blowfish_bytes(encrypted_data, blowfish_key)
            else:
                flash("Unsupported file encryption type.", "danger")
                return render_template("view_note.html", note=note, decrypted=decrypted)

            # Save decrypted file to temp folder
            temp_folder = os.path.join(current_app.root_path, 'static', 'temp')
            os.makedirs(temp_folder, exist_ok=True)
            decrypted_path = os.path.join(temp_folder, note.file_path)
            with open(decrypted_path, 'wb') as out_file:
                out_file.write(decrypted_data)
            if os.path.exists(decrypted_path):
                file_url = url_for('static', filename=f'temp/{note.file_path}')
            else:
                print("Decrypted file was not saved:", decrypted_path)
        except Exception as e:
            flash(f"File decryption failed: {e}", "danger")

    if not share_link and note.share_token:
        share_link = url_for("notes.shared_note", token=note.share_token, _external=True)
        qr = qrcode.make(share_link)
        buf = io.BytesIO()
        qr.save(buf, format='PNG')
        qr_code_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')

    return render_template(
        "view_note.html",
        note=note,
        decrypted=decrypted,
        file_url=file_url,
        file_ext=file_ext,
        share_link=share_link,
        qr_code_base64=qr_code_base64,
        qr_image_url=qr_image_url
    )

def send_otp_email(to_email, otp_code):
    msg = EmailMessage()
    msg.set_content(f"Your Securanote OTP code is: {otp_code}")
    msg["Subject"] = "Securanote OTP Verification"
    msg["From"] = "securanote@gmail.com"
    msg["To"] = to_email
    with smtplib.SMTP("smtp.gmail.com", 587) as server:
        server.starttls()
        server.login("securanote@gmail.com", "nyyq xzom ptoy fgjv")
        server.send_message(msg)

# ------------------------ View Encrypted File ------------------------
@notes_bp.route('/view_file/<filename>')
@login_required
def view_file(filename):
    note = Note.query.filter_by(file_path=filename, user_id=current_user.id).first()
    if not note or not note.file_data:
        abort(404)

    file_path = os.path.join(current_app.root_path, 'static', 'uploads', filename)
    try:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
        if note.encryption_type == 'AES':
            decrypted_data = fernet.decrypt(encrypted_data)
        elif note.encryption_type == 'ChaCha':
            decrypted_data = decrypt_chacha_bytes(encrypted_data)
        elif note.encryption_type == 'Blowfish':
            decrypted_data = decrypt_blowfish_bytes(encrypted_data, blowfish_key)
        else:
            abort(400, description="Unsupported encryption type.")
    except Exception as e:
        abort(500, description=f"File decryption failed: {str(e)}")

    mimetype = mimetypes.guess_type(filename)[0] or 'application/octet-stream'
    return send_file(
        io.BytesIO(decrypted_data),
        mimetype=mimetype,
        as_attachment=False,
        download_name=filename
    )

@notes_bp.route("/verify_email_for_reset/<int:note_id>", methods=["GET", "POST"])
@login_required
def verify_email_for_reset(note_id):
    note = Note.query.get_or_404(note_id)
    if note.user_id != current_user.id:
        abort(403)
    if request.method == "POST":
        otp_code = str(random.randint(100000, 999999))
        note.otp_code = otp_code
        note.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
        db.session.commit()
        print("Sending OTP:", otp_code)
        from securanote import send_otp
        send_otp(current_user.email, otp_code)
        return redirect(url_for("notes.verify_otp", note_id=note.id))
    return render_template("verify_email.html", note=note)

# ------------------------ Export PDF ------------------------
@notes_bp.route('/export_pdf', methods=['POST'])
@login_required
def export_pdf():
    title = request.form.get('title')
    content = request.form.get('content')
    filename = request.form.get('file_path')
    if not title or not content:
        flash("Missing data for PDF export.", "error")
        return redirect(url_for('notes.dashboard'))

    buffer = io.BytesIO()
    p = canvas.Canvas(buffer)
    p.setTitle(f"{title}.pdf")

    p.setFont("Helvetica-Bold", 16)
    p.drawString(50, 800, title)
    p.setFont("Helvetica", 12)
    y = 780
    for line in content.splitlines():
        if y < 100:
            p.showPage()
            y = 800
            p.setFont("Helvetica", 12)
        p.drawString(50, y, line)
        y -= 15

    if filename:
        ext = filename.rsplit('.', 1)[-1].lower()
        note = Note.query.filter_by(file_path=filename, user_id=current_user.id).first()
        if note:
            encrypted_data = download_file_from_s3(filename)
            if not encrypted_data:
                flash("Failed to fetch file from S3.", "error")
                return redirect(url_for("notes.view_note", note_id=note.id))
            try:
                if note.encryption_type == 'AES':
                    decrypted_data = fernet.decrypt(encrypted_data)
                elif note.encryption_type == 'ChaCha':
                    decrypted_data = decrypt_chacha_bytes(encrypted_data)
                elif note.encryption_type == 'Blowfish':
                    decrypted_data = decrypt_blowfish_bytes(encrypted_data, blowfish_key)
                else:
                    flash("Unsupported encryption type.", "error")
                    return redirect(url_for("notes.view_note", note_id=note.id))
            except Exception as e:
                flash(f"Decryption failed: {e}", "error")
                return redirect(url_for("notes.view_note", note_id=note.id))

            if ext in ['jpg', 'jpeg', 'png']:
                try:
                    image = Image.open(io.BytesIO(decrypted_data))
                    image = image.convert('RGB')
                    temp_img = io.BytesIO()
                    image.save(temp_img, format='JPEG')
                    temp_img.seek(0)
                    img_reader = ImageReader(temp_img)
                    iw, ih = img_reader.getSize()
                    max_width = 400
                    if iw > max_width:
                        scale = max_width / iw
                        iw = max_width
                        ih = int(ih * scale)
                    y_img = y - ih - 20
                    if y_img < 100:
                        p.showPage()
                        y_img = 700
                    p.drawImage(img_reader, 50, y_img, width=iw, height=ih)
                    y = y_img - 20
                except Exception as img_err:
                    flash(f"Image rendering failed: {img_err}", "warning")
            elif ext in ['mp3', 'mp4']:
                y -= 30
                p.setFont("Helvetica-Oblique", 12)
                p.drawString(50, y, f"{ext.upper()} file ({filename}) cannot be embedded in PDF.")

    p.save()
    buffer.seek(0)
    return send_file(
        buffer,
        as_attachment=True,
        download_name=f"{title}.pdf",
        mimetype='application/pdf'
    )

@notes_bp.route("/shared/<token>", methods=["GET"])
def shared_note(token):
    note = Note.query.filter_by(share_token=token).first_or_404()
    if note.views_left is not None and note.views_left <= 0:
        return "<h3>This note is no longer available (view limit reached).</h3>"
    try:
        if note.encryption_type == 'AES':
            decrypted = fernet.decrypt(note.encrypted_content.encode()).decode()
        elif note.encryption_type == 'ChaCha':
            decrypted = decrypt_chacha(note.encrypted_content)
        elif note.encryption_type == 'Blowfish':
            decrypted = decrypt_blowfish(note.encrypted_content, blowfish_key)
        else:
            return "<h3>Unsupported encryption.</h3>"
    except Exception as e:
        return f"<h3>Decryption error: {e}</h3>"

    file_url = None
    file_ext = None
    if note.file_path:
        file_ext = note.file_path.rsplit('.', 1)[-1].lower()
        temp_folder = os.path.join(current_app.root_path, 'static', 'temp')
        os.makedirs(temp_folder, exist_ok=True)
        decrypted_path = os.path.join(temp_folder, note.file_path)
        if not os.path.exists(decrypted_path):
            encrypted_data = download_file_from_s3(note.file_path)
            if encrypted_data:
                try:
                    if note.encryption_type == 'AES':
                        decrypted_data = fernet.decrypt(encrypted_data)
                    elif note.encryption_type == 'ChaCha':
                        decrypted_data = decrypt_chacha_bytes(encrypted_data)
                    elif note.encryption_type == 'Blowfish':
                        decrypted_data = decrypt_blowfish_bytes(encrypted_data, blowfish_key)
                    else:
                        return "<h3>Unsupported file encryption.</h3>"
                    with open(decrypted_path, 'wb') as f:
                        f.write(decrypted_data)
                except Exception as e:
                    return f"<h3>File decryption error: {e}</h3>"
        file_url = url_for('static', filename=f'temp/{note.file_path}')

    rendered = render_template(
        "shared_note.html",
        note=note,
        decrypted=decrypted,
        file_url=file_url,
        file_ext=file_ext
    )
    user_agent = request.headers.get("User-Agent", "").lower()
    preview_bots = ['discordbot', 'facebookexternalhit', 'whatsapp', 'telegrambot', 'twitterbot', 'slackbot']
    is_preview = any(bot in user_agent for bot in preview_bots)
    if not is_preview and note.views_left is not None:
        note.views_left -= 1
        db.session.commit()
    return rendered

@notes_bp.route("/temp_media/<key>/<filename>")
def serve_temp_media(key, filename):
    decrypted_data = session.get(key)
    if not decrypted_data:
        abort(404)
    session.pop(key)
    mime_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    return current_app.response_class(decrypted_data, mimetype=mime_type)

# ------------------------ Edit Note (PIN Protected) ------------------------
@notes_bp.route("/edit/<int:note_id>/pin", methods=["GET", "POST"])
@login_required
def verify_edit_pin(note_id):
    note = Note.query.get_or_404(note_id)
    if note.user_id != current_user.id:
        abort(403)
    if request.method == "POST":
        entered_pin = request.form.get("pin")
        if check_password_hash(note.pin_hash, entered_pin):
            session[f'edit_verified_{note_id}'] = True
            session[f'pin_used_{note_id}'] = entered_pin
            return redirect(url_for('notes.edit_note', note_id=note_id))
        else:
            flash("Incorrect PIN", "error")

    return render_template("verify_edit_pin.html", note=note)

@notes_bp.route('/edit/<int:note_id>', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.user_id != current_user.id:
        abort(403)
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        encryption_type = request.form.get('encryption_type')
        if not title or not content:
            flash('Title and content are required.', 'error')
            return redirect(url_for('notes.edit_note', note_id=note_id))
        try:
            if encryption_type == 'AES':
                encrypted = fernet.encrypt(content.encode()).decode()
            elif encryption_type == 'ChaCha':
                encrypted = encrypt_chacha(content.encode())
            elif encryption_type == 'Blowfish':
                encrypted = encrypt_blowfish(content.encode(), blowfish_key)
            else:
                flash('Invalid encryption type selected.', 'error')
                return redirect(url_for('notes.edit_note', note_id=note_id))
        except Exception as e:
            flash(f'Encryption error: {str(e)}', 'error')
            return redirect(url_for('notes.edit_note', note_id=note_id))
        note.title = title
        note.encrypted_content = encrypted
        note.encryption_type = encryption_type
        note.timestamp = datetime.utcnow()
        try:
            db.session.commit()
            flash('Note updated successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Failed to update note: {str(e)}', 'error')
        return redirect(url_for('notes.view_note', note_id=note.id))

    try:
        if note.encryption_type == 'AES':
            decrypted_content = fernet.decrypt(note.encrypted_content.encode()).decode()
        elif note.encryption_type == 'ChaCha':
            decrypted_content = decrypt_chacha(note.encrypted_content)
        elif note.encryption_type == 'Blowfish':
            decrypted_content = decrypt_blowfish(note.encrypted_content, blowfish_key)
        else:
            decrypted_content = ""
    except Exception as e:
        flash(f'Error decrypting note: {str(e)}', 'error')
        decrypted_content = ""

    return render_template('edit_note.html', note=note, decrypted_content=decrypted_content)

@notes_bp.route("/note/<int:note_id>/verify-otp", methods=["GET", "POST"])
@login_required
def verify_otp(note_id):
    note = Note.query.get_or_404(note_id)
    if note.user_id != current_user.id:
        abort(403)
    if request.method == "POST":
        otp_input = request.form.get("otp")
        if str(note.otp_code) == str(otp_input) and note.otp_expiry > datetime.utcnow():
            return redirect(url_for("notes.reset_pin", note_id=note.id))
        else:
            flash("Invalid or expired OTP", "danger")
    return render_template("verify_otp.html", note=note)

@notes_bp.route("/note/<int:note_id>/reset-pin", methods=["GET", "POST"])
@login_required
def reset_pin(note_id):
    note = Note.query.get_or_404(note_id)
    if note.user_id != current_user.id:
        abort(403)
    if request.method == "POST":
        new_pin = request.form.get("new_pin")
        note.pin_hash = generate_password_hash(new_pin)
        note.wrong_attempts = 0
        note.otp_code = None
        note.otp_expiry = None
        db.session.commit()
        flash("PIN reset successful. You can now access your note.", "success")
        return redirect(url_for("notes.view_note", note_id=note.id))
    return render_template("reset_pin.html", note=note)

@notes_bp.route("/note/<int:note_id>/resend-otp", methods=["POST"])
@login_required
def resend_otp(note_id):
    note = Note.query.get_or_404(note_id)
    if note.user_id != current_user.id:
        abort(403)
    otp_code = str(random.randint(100000, 999999))
    note.otp_code = otp_code
    note.otp_expiry = datetime.utcnow() + timedelta(minutes=5)
    db.session.commit()
    send_otp_email(current_user.email, otp_code)
    flash("A new OTP has been sent to your email.", "info")
    return redirect(url_for("notes.verify_otp", note_id=note.id))

# ------------------------ Delete Note ------------------------
@notes_bp.route('/delete_note/<int:note_id>', methods=['POST'])
@login_required
def delete_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.user_id != current_user.id:
        flash('Unauthorized action', 'error')
        return redirect(url_for('notes.dashboard'))
    db.session.delete(note)
    db.session.commit()
    flash('Note deleted.', 'success')
    return redirect(url_for('notes.dashboard'))
