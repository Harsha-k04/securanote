from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, session, current_app, send_file
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os, io, uuid, base64, mimetypes, random, qrcode
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader
from PIL import Image
from email.message import EmailMessage
import smtplib

from securanote.supabase_client import supabase
from securanote.models import Note
from securanote.utils import (
    encrypt_blowfish, decrypt_blowfish,
    encrypt_blowfish_bytes, decrypt_blowfish_bytes,
    blowfish_key,
    encrypt_chacha, decrypt_chacha, decrypt_chacha_bytes,
    upload_file_to_s3, download_file_from_s3,
    fernet
)
from securanote import send_otp

load_dotenv()

notes_bp = Blueprint('notes', __name__)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp3', 'mp4', 'pdf'}
UPLOAD_FOLDER = os.path.join('static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


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


# ------------------------ DASHBOARD & ADD NOTE ------------------------
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

        # File upload
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

        note_data = {
            "title": title,
            "encrypted_content": encrypted_content,
            "encryption_type": encryption_type,
            "user_id": current_user.id,
            "timestamp": datetime.utcnow().isoformat(),
            "pin_hash": pin_hash,
            "file_path": filename
            
        }

        if request.form.get("share_note") == "yes":
            note_data["share_token"] = uuid.uuid4().hex
            note_data["views_left"] = 1
            note_data["share_expiry"] = None

        supabase.table("notes").insert(note_data).execute()
        flash('Note added successfully.', 'success')
        return redirect(url_for('notes.dashboard'))

    resp = supabase.table("notes").select("*").eq("user_id", current_user.id).order("timestamp", desc=True).execute()
    user_notes = [Note.from_dict(n) for n in resp.data] if resp.data else []
    return render_template('dashboard.html', notes=user_notes, user=current_user)


# ------------------------ VIEW NOTE ------------------------
@notes_bp.route("/note/<int:note_id>/view", methods=["GET", "POST"])
@login_required
def view_note(note_id):
    resp = supabase.table("notes").select("*").eq("id", note_id).execute()
    if not resp.data:
        abort(404)
    note = Note.from_dict(resp.data[0])
    if note.user_id != current_user.id:
        abort(403)

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

    decrypted = None
    try:
        if note.encryption_type == 'AES':
            decrypted = fernet.decrypt(note.encrypted_content.encode()).decode()
        elif note.encryption_type == 'ChaCha':
            decrypted = decrypt_chacha(note.encrypted_content)
        elif note.encryption_type == 'Blowfish':
            decrypted = decrypt_blowfish(note.encrypted_content, blowfish_key)
    except Exception:
        flash("Decryption failed", "danger")

    file_url = None
    file_ext = None
    if note.file_path:
        file_ext = note.file_path.rsplit('.', 1)[-1].lower()
        try:
            encrypted_data = download_file_from_s3(note.file_path)
            if encrypted_data:
                if note.encryption_type == 'AES':
                    decrypted_data = fernet.decrypt(encrypted_data)
                elif note.encryption_type == 'ChaCha':
                    decrypted_data = decrypt_chacha_bytes(encrypted_data)
                elif note.encryption_type == 'Blowfish':
                    decrypted_data = decrypt_blowfish_bytes(encrypted_data, blowfish_key)
                temp_folder = os.path.join(current_app.root_path, 'static', 'temp')
                os.makedirs(temp_folder, exist_ok=True)
                decrypted_path = os.path.join(temp_folder, note.file_path)
                with open(decrypted_path, 'wb') as f:
                    f.write(decrypted_data)
                file_url = url_for('static', filename=f'temp/{note.file_path}')
        except Exception as e:
            flash(f"File decryption failed: {e}", "danger")

    return render_template("view_note.html", note=note, decrypted=decrypted, file_url=file_url, file_ext=file_ext)


# ------------------------ EDIT NOTE ------------------------
@notes_bp.route("/edit/<int:note_id>/pin", methods=["GET", "POST"])
@login_required
def verify_edit_pin(note_id):
    resp = supabase.table("notes").select("*").eq("id", note_id).execute()
    if not resp.data:
        abort(404)
    note = Note.from_dict(resp.data[0])
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
    resp = supabase.table("notes").select("*").eq("id", note_id).execute()
    if not resp.data:
        abort(404)
    note = Note.from_dict(resp.data[0])
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

        supabase.table("notes").update({
            "title": title,
            "encrypted_content": encrypted,
            "encryption_type": encryption_type,
            "timestamp": datetime.utcnow().isoformat()
        }).eq("id", note_id).execute()
        flash('Note updated successfully!', 'success')
        return redirect(url_for('notes.view_note', note_id=note_id))

    decrypted_content = ''
    try:
        if note.encryption_type == 'AES':
            decrypted_content = fernet.decrypt(note.encrypted_content.encode()).decode()
        elif note.encryption_type == 'ChaCha':
            decrypted_content = decrypt_chacha(note.encrypted_content)
        elif note.encryption_type == 'Blowfish':
            decrypted_content = decrypt_blowfish(note.encrypted_content, blowfish_key)
    except Exception:
        decrypted_content = ''

    return render_template('edit_note.html', note=note, decrypted_content=decrypted_content)


# ------------------------ OTP RESET ------------------------
@notes_bp.route("/verify_email_for_reset/<int:note_id>", methods=["GET", "POST"])
@login_required
def verify_email_for_reset(note_id):
    resp = supabase.table("notes").select("*").eq("id", note_id).execute()
    if not resp.data:
        abort(404)
    note = Note.from_dict(resp.data[0])
    if note.user_id != current_user.id:
        abort(403)

    if request.method == "POST":
        otp_code = str(random.randint(100000, 999999))
        supabase.table("notes").update({
            "otp_code": otp_code,
            "otp_expiry": (datetime.utcnow() + timedelta(minutes=5)).isoformat()
        }).eq("id", note_id).execute()
        send_otp(current_user.email, otp_code)
        return redirect(url_for("notes.verify_otp", note_id=note.id))
    return render_template("verify_email.html", note=note)


@notes_bp.route("/note/<int:note_id>/verify-otp", methods=["GET", "POST"])
@login_required
def verify_otp(note_id):
    resp = supabase.table("notes").select("*").eq("id", note_id).execute()
    if not resp.data:
        abort(404)
    note = Note.from_dict(resp.data[0])
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
    resp = supabase.table("notes").select("*").eq("id", note_id).execute()
    if not resp.data:
        abort(404)
    note = Note.from_dict(resp.data[0])
    if note.user_id != current_user.id:
        abort(403)

    if request.method == "POST":
        new_pin = request.form.get("new_pin")
        supabase.table("notes").update({
            "pin_hash": generate_password_hash(new_pin),
            "otp_code": None,
            "otp_expiry": None,
            "wrong_attempts": 0
        }).eq("id", note_id).execute()
        flash("PIN reset successful. You can now access your note.", "success")
        return redirect(url_for("notes.view_note", note_id=note.id))
    return render_template("reset_pin.html", note=note)


@notes_bp.route("/note/<int:note_id>/resend-otp", methods=["POST"])
@login_required
def resend_otp(note_id):
    otp_code = str(random.randint(100000, 999999))
    supabase.table("notes").update({
        "otp_code": otp_code,
        "otp_expiry": (datetime.utcnow() + timedelta(minutes=5)).isoformat()
    }).eq("id", note_id).execute()
    send_otp_email(current_user.email, otp_code)
    flash("A new OTP has been sent to your email.", "info")
    return redirect(url_for("notes.verify_otp", note_id=note_id))

# ------------------------ SHARE NOTE (QR CODE) ------------------------
@notes_bp.route('/note/<int:note_id>/share', methods=['GET'])
@login_required
def share_note(note_id):
    resp = supabase.table("notes").select("*").eq("id", note_id).execute()
    if not resp.data:
        abort(404)
    note = Note.from_dict(resp.data[0])
    if note.user_id != current_user.id:
        abort(403)

    if not note.share_token:
        share_token = uuid.uuid4().hex
        supabase.table("notes").update({
            "share_token": share_token,
            "views_left": 1,
            "share_expiry": (datetime.utcnow() + timedelta(days=1)).isoformat()
        }).eq("id", note_id).execute()
    else:
        share_token = note.share_token

    share_url = url_for('notes.view_shared_note', token=share_token, _external=True)
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(share_url)
    qr.make(fit=True)
    img = qr.make_image(fill='black', back_color='white')
    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)
    return send_file(buf, mimetype='image/png', download_name=f'share_qr_{note_id}.png')


@notes_bp.route('/shared/<token>', methods=['GET'])
def view_shared_note(token):
    resp = supabase.table("notes").select("*").eq("share_token", token).execute()
    if not resp.data:
        abort(404)
    note = Note.from_dict(resp.data[0])

    if note.views_left <= 0 or (note.share_expiry and datetime.fromisoformat(note.share_expiry) < datetime.utcnow()):
        flash("This shared note has expired or has no remaining views.", "danger")
        return redirect(url_for('notes.dashboard'))

    # Decrypt content
    decrypted = ''
    try:
        if note.encryption_type == 'AES':
            decrypted = fernet.decrypt(note.encrypted_content.encode()).decode()
        elif note.encryption_type == 'ChaCha':
            decrypted = decrypt_chacha(note.encrypted_content)
        elif note.encryption_type == 'Blowfish':
            decrypted = decrypt_blowfish(note.encrypted_content, blowfish_key)
    except Exception:
        flash("Failed to decrypt shared note.", "danger")

    # Reduce views_left by 1
    supabase.table("notes").update({
        "views_left": note.views_left - 1
    }).eq("id", note.id).execute()

    return render_template("view_shared_note.html", note=note, decrypted=decrypted)


# ------------------------ EXPORT NOTE AS PDF ------------------------
@notes_bp.route('/note/<int:note_id>/export_pdf', methods=['GET'])
@login_required
def export_pdf(note_id):
    resp = supabase.table("notes").select("*").eq("id", note_id).execute()
    if not resp.data:
        abort(404)
    note = Note.from_dict(resp.data[0])
    if note.user_id != current_user.id:
        abort(403)

    # Decrypt content
    decrypted_content = ''
    try:
        if note.encryption_type == 'AES':
            decrypted_content = fernet.decrypt(note.encrypted_content.encode()).decode()
        elif note.encryption_type == 'ChaCha':
            decrypted_content = decrypt_chacha(note.encrypted_content)
        elif note.encryption_type == 'Blowfish':
            decrypted_content = decrypt_blowfish(note.encrypted_content, blowfish_key)
    except Exception:
        flash("Failed to decrypt note for PDF export.", "danger")
        return redirect(url_for('notes.view_note', note_id=note_id))

    pdf_buffer = io.BytesIO()
    c = canvas.Canvas(pdf_buffer)
    c.setFont("Helvetica", 12)
    textobject = c.beginText(40, 800)
    textobject.textLine(f"Title: {note.title}")
    textobject.textLine(f"Created: {note.timestamp}")
    textobject.textLine("")
    for line in decrypted_content.splitlines():
        textobject.textLine(line)
    c.drawText(textobject)

    # Include image/file if present
    if note.file_path:
        try:
            encrypted_data = download_file_from_s3(note.file_path)
            if note.encryption_type == 'AES':
                decrypted_data = fernet.decrypt(encrypted_data)
            elif note.encryption_type == 'ChaCha':
                decrypted_data = decrypt_chacha_bytes(encrypted_data)
            elif note.encryption_type == 'Blowfish':
                decrypted_data = decrypt_blowfish_bytes(encrypted_data, blowfish_key)
            img = Image.open(io.BytesIO(decrypted_data))
            c.drawInlineImage(ImageReader(img), 50, 400, width=400, height=300)
        except Exception:
            pass

    c.showPage()
    c.save()
    pdf_buffer.seek(0)
    return send_file(pdf_buffer, as_attachment=True, download_name=f"{note.title}.pdf", mimetype='application/pdf')


# ------------------------ DELETE NOTE ------------------------
@notes_bp.route('/delete_note/<int:note_id>', methods=['POST'])
@login_required
def delete_note(note_id):
    resp = supabase.table("notes").select("*").eq("id", note_id).execute()
    if not resp.data:
        abort(404)
    note = Note.from_dict(resp.data[0])
    if note.user_id != current_user.id:
        flash('Unauthorized action', 'error')
        return redirect(url_for('notes.dashboard'))

    supabase.table("notes").delete().eq("id", note_id).execute()
    flash('Note deleted.', 'success')
    return redirect(url_for('notes.dashboard'))
