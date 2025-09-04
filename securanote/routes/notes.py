from flask import Blueprint, render_template, request, redirect, url_for, flash, abort, session, current_app, send_file
from flask_login import login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
from securanote.supabase_client import supabase
from securanote.models import Note
from securanote.utils import (
    encrypt_blowfish, decrypt_blowfish,
    encrypt_blowfish_bytes, decrypt_blowfish_bytes,
    blowfish_key,
    encrypt_chacha, decrypt_chacha, decrypt_chacha_bytes,
    fernet,
    upload_file_to_s3, download_file_from_s3
)
import uuid, os, io, base64, mimetypes, random, qrcode

notes_bp = Blueprint('notes', __name__)
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp3', 'mp4', 'pdf'}

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

        # Handle file upload
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
            upload_file_to_s3(encrypted_file_data, filename)

        # Save note to Supabase
        note_data = {
            "user_id": current_user.id,
            "title": title,
            "encrypted_content": encrypted_content,
            "encryption_type": encryption_type,
            "pin_hash": pin_hash,
            "file_path": filename,
            "file_data": encrypted_file_data,
            "timestamp": datetime.utcnow().isoformat()
        }
        if request.form.get("share_note") == "yes":
            note_data["share_token"] = uuid.uuid4().hex
            note_data["views_left"] = 1
        supabase.table("notes").insert(note_data).execute()

        flash('Note added successfully.', 'success')
        return redirect(url_for('notes.dashboard'))

    # Fetch user notes
    resp = supabase.table("notes").select("*").eq("user_id", current_user.id).order("timestamp", desc=True).execute()
    user_notes = [Note.from_dict(n) for n in resp.data] if resp.data else []
    return render_template('dashboard.html', notes=user_notes, user=current_user)


# ------------------------ View Note ------------------------
@notes_bp.route("/note/<int:note_id>/view", methods=["GET", "POST"])
@login_required
def view_note(note_id):
    resp = supabase.table("notes").select("*").eq("id", note_id).execute()
    if not resp.data:
        abort(404)
    note = resp.data[0]

    if note["user_id"] != current_user.id:
        abort(403)

    file_url = None
    file_ext = None
    decrypted = None
    share_link = None
    qr_image_url = None
    qr_code_base64 = None

    # PIN session attempts
    attempt_key = f"attempts_note_{note_id}"
    session.setdefault(attempt_key, 0)

    if request.method == "POST":
        if "pin" in request.form:
            entered_pin = request.form["pin"]
            if check_password_hash(note["pin_hash"], entered_pin):
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
            share_token = uuid.uuid4().hex
            updates = {"share_token": share_token, "views_left": 1 if view_once else None}
            supabase.table("notes").update(updates).eq("id", note_id).execute()
            share_link = url_for("notes.shared_note", token=share_token, _external=True)
            qr = qrcode.make(share_link)
            filename = f"{note_id}_qr.png"
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

    # Decrypt content
    try:
        if note["encryption_type"] == 'AES':
            decrypted = fernet.decrypt(note["encrypted_content"].encode()).decode()
        elif note["encryption_type"] == 'ChaCha':
            decrypted = decrypt_chacha(note["encrypted_content"])
        elif note["encryption_type"] == 'Blowfish':
            decrypted = decrypt_blowfish(note["encrypted_content"], blowfish_key)
        else:
            flash("Unsupported encryption type.", "danger")
            return render_template("enter_pin.html", note=note)
    except Exception as e:
        flash(f"Decryption failed: {e}", "danger")
        return render_template("enter_pin.html", note=note)

    # Decrypt file if exists
    if note.get("file_path"):
        file_ext = note["file_path"].rsplit('.', 1)[-1].lower()
        try:
            encrypted_data = download_file_from_s3(note["file_path"])
            if encrypted_data:
                if note["encryption_type"] == 'AES':
                    decrypted_data = fernet.decrypt(encrypted_data)
                elif note["encryption_type"] == 'ChaCha':
                    decrypted_data = decrypt_chacha_bytes(encrypted_data)
                elif note["encryption_type"] == 'Blowfish':
                    decrypted_data = decrypt_blowfish_bytes(encrypted_data, blowfish_key)
                temp_folder = os.path.join(current_app.root_path, 'static', 'temp')
                os.makedirs(temp_folder, exist_ok=True)
                decrypted_path = os.path.join(temp_folder, note["file_path"])
                with open(decrypted_path, 'wb') as f:
                    f.write(decrypted_data)
                file_url = url_for('static', filename=f'temp/{note["file_path"]}')
        except Exception as e:
            flash(f"File decryption failed: {e}", "danger")

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


# ------------------------ Shared Note ------------------------
@notes_bp.route("/shared/<token>", methods=["GET"])
def shared_note(token):
    resp = supabase.table("notes").select("*").eq("share_token", token).execute()
    if not resp.data:
        return "<h3>This note is no longer available.</h3>"
    note = resp.data[0]

    if note.get("views_left") is not None and note["views_left"] <= 0:
        return "<h3>This note is no longer available (view limit reached).</h3>"

    # Decrypt content
    try:
        if note["encryption_type"] == 'AES':
            decrypted = fernet.decrypt(note["encrypted_content"].encode()).decode()
        elif note["encryption_type"] == 'ChaCha':
            decrypted = decrypt_chacha(note["encrypted_content"])
        elif note["encryption_type"] == 'Blowfish':
            decrypted = decrypt_blowfish(note["encrypted_content"], blowfish_key)
        else:
            return "<h3>Unsupported encryption.</h3>"
    except Exception as e:
        return f"<h3>Decryption error: {e}</h3>"

    file_url = None
    if note.get("file_path"):
        temp_folder = os.path.join(current_app.root_path, 'static', 'temp')
        os.makedirs(temp_folder, exist_ok=True)
        decrypted_path = os.path.join(temp_folder, note["file_path"])
        if not os.path.exists(decrypted_path):
            encrypted_data = download_file_from_s3(note["file_path"])
            if encrypted_data:
                try:
                    if note["encryption_type"] == 'AES':
                        decrypted_data = fernet.decrypt(encrypted_data)
                    elif note["encryption_type"] == 'ChaCha':
                        decrypted_data = decrypt_chacha_bytes(encrypted_data)
                    elif note["encryption_type"] == 'Blowfish':
                        decrypted_data = decrypt_blowfish_bytes(encrypted_data, blowfish_key)
                    with open(decrypted_path, 'wb') as f:
                        f.write(decrypted_data)
                except Exception as e:
                    return f"<h3>File decryption error: {e}</h3>"
        file_url = url_for('static', filename=f'temp/{note["file_path"]}')

    # Decrement views_left if not a preview bot
    user_agent = request.headers.get("User-Agent", "").lower()
    preview_bots = ['discordbot', 'facebookexternalhit', 'whatsapp', 'telegrambot', 'twitterbot', 'slackbot']
    if not any(bot in user_agent for bot in preview_bots) and note.get("views_left") is not None:
        new_views = note["views_left"] - 1
        supabase.table("notes").update({"views_left": new_views}).eq("id", note["id"]).execute()

    return render_template("shared_note.html", note=note, decrypted=decrypted, file_url=file_url, file_ext=file_url.rsplit('.',1)[-1] if file_url else None)
