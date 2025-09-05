# securanote/ai_routes.py
import os
import random
from datetime import datetime
from flask import Blueprint, request, render_template, jsonify, redirect, url_for, flash
from flask_login import login_required, current_user
import requests
import logging
import time
from werkzeug.security import generate_password_hash

from securanote.models import Note
from securanote import supabase

# Import crypto utilities used for decryption/encryption
from securanote.utils import (
    fernet,
    decrypt_chacha,
    decrypt_blowfish,
    blowfish_key,
    encrypt_content
)

# ==============================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

ai_bp = Blueprint("ai", __name__, url_prefix="/ai")

# ==============================
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    logger.error("GEMINI_API_KEY not found in environment.")
    raise RuntimeError("Missing GEMINI_API_KEY")

GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

def gemini_generate(prompt, retries=3, backoff=2):
    headers = {
        "Content-Type": "application/json",
        "X-goog-api-key": GEMINI_API_KEY
    }
    payload = {
        "contents": [
            {"parts": [{"text": prompt}]}
        ]
    }

    attempt = 0
    while attempt < retries:
        try:
            response = requests.post(GEMINI_API_URL, json=payload, headers=headers, timeout=20)
            if response.status_code == 200:
                data = response.json()
                candidate = data.get("candidates", [{}])[0]
                content = candidate.get("content", {})
                parts = content.get("parts", [])
                texts = [part.get("text", "") for part in parts if "text" in part]
                return "\n".join(texts).strip() if texts else "No response from Gemini."
            else:
                logger.error(f"Gemini API Error {response.status_code}: {response.text}")
                if 500 <= response.status_code < 600:
                    attempt += 1
                    time.sleep(backoff ** attempt)
                    continue
                return f"Gemini API Error {response.status_code}: {response.text}"
        except requests.exceptions.RequestException as e:
            attempt += 1
            logger.warning(f"Request failed (attempt {attempt}/{retries}): {e}")
            time.sleep(backoff ** attempt)
    return f"Gemini API failed after {retries} attempts."

# ==============================
@ai_bp.route("/assistant", methods=["GET", "POST"])
@login_required
def assistant():
    if request.is_json:
        data = request.get_json()
        query = data.get("query", "").strip()
        note_content = data.get("note_content", "")
        note_id = data.get("note_id")

        # Try to fetch and decrypt the note content if note_id is provided
        decrypted_content = ""
        if note_id:
            try:
                note_resp = supabase.table("notes").select("*").eq("id", int(note_id)).eq("user_id", current_user.id).execute()
                if note_resp.data:
                    note = Note.from_dict(note_resp.data[0])
                    try:
                        if note.encryption_type == "AES":
                            decrypted_content = fernet.decrypt(note.encrypted_content.encode()).decode()
                        elif note.encryption_type == "ChaCha":
                            decrypted_content = decrypt_chacha(note.encrypted_content)
                        elif note.encryption_type == "Blowfish":
                            decrypted_content = decrypt_blowfish(note.encrypted_content, blowfish_key)
                    except Exception as e:
                        logger.warning("Decryption failed for note_id %s: %s", note_id, e)
            except Exception as e:
                logger.warning("Failed to fetch/decrypt note: %s", e)

        # Fallback to passed note_content if decryption didn’t work
        if not decrypted_content:
            decrypted_content = note_content or ""

        if not decrypted_content:
            return jsonify({"response": "Note content is empty or could not be decrypted."})

        # Build AI prompt dynamically based on user query
        try:
            if not query:
                # Default action = summarize if no query
                prompt = f"Summarize this note into concise points:\n{decrypted_content}"
            else:
                # Use the query directly for Gemini
                prompt = (
                    f"You are an AI assistant. The user has a note and a query.\n\n"
                    f"Note:\n{decrypted_content}\n\n"
                    f"User query: {query}\n\n"
                    f"Provide the best possible response."
                )

            ai_response = gemini_generate(prompt)
        except Exception as e:
            logger.exception("AI generation error: %s", e)
            ai_response = f"Error generating AI response: {e}"

        return jsonify({"response": ai_response})

    # GET: Render a simple assistant page
    resp = supabase.table("notes").select("*").eq("user_id", current_user.id).execute()
    notes_data = resp.data if resp.data else []
    notes = [Note.from_dict(n) for n in notes_data]
    return render_template("ai_assistant.html", user=current_user, notes=notes, ai_response=None)

# ==============================
@ai_bp.route("/save-ai-note", methods=["POST"])
@login_required
def save_ai_note():
    title = request.form.get("title")
    content = request.form.get("content")

    if not title or not content:
        flash("Title and content are required to save the note.", "error")
        return redirect(url_for("notes.dashboard"))

    try:
        encrypted = fernet.encrypt(content.encode()).decode()
    except Exception as e:
        logger.exception("Failed to encrypt AI note: %s", e)
        flash("Failed to encrypt AI-generated note.", "error")
        return redirect(url_for("notes.dashboard"))

    supabase.table("notes").insert({
        "user_id": current_user.id,
        "title": title,
        "encrypted_content": encrypted,
        "encryption_type": "AES",
        "pin_hash": generate_password_hash("0000"),
        "timestamp": datetime.utcnow().isoformat()
    }).execute()

    flash("AI-generated note saved successfully!", "success")
    return redirect(url_for("notes.dashboard"))
