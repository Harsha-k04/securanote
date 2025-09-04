import os
import random
from datetime import datetime
from flask import Blueprint, request, render_template, jsonify, redirect, url_for, flash
from flask_login import login_required, current_user
import requests
import logging
import time

from securanote.models import Note
from securanote import supabase

# ==============================
# Logging Setup
# ==============================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ==============================
# Blueprint
# ==============================
ai_bp = Blueprint("ai", __name__, url_prefix="/ai")

# ==============================
# Gemini 2.0 API Setup
# ==============================
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    logger.error("GEMINI_API_KEY not found in environment. Set it in your venv before running.")
    raise RuntimeError("Missing GEMINI_API_KEY")

GEMINI_API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

# ==============================
# Gemini Generate with Retry
# ==============================
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
            response = requests.post(GEMINI_API_URL, json=payload, headers=headers)
            if response.status_code == 200:
                data = response.json()
                # Safely extract text from candidates -> content -> parts -> text
                candidate = data.get("candidates", [{}])[0]
                content_list = candidate.get("content", [])

                if isinstance(content_list, list):
                    texts = []
                    for part in content_list:
                        if isinstance(part, dict) and "text" in part:
                            texts.append(part["text"])
                    return "\n".join(texts).strip()
                else:
                    return str(content_list).strip()
            else:
                logger.error(f"Gemini API Error {response.status_code}: {response.text}")
                return f"Gemini API Error {response.status_code}: {response.text}"
        except requests.exceptions.RequestException as e:
            attempt += 1
            logger.warning(f"Request failed (attempt {attempt}/{retries}): {e}")
            time.sleep(backoff ** attempt)
    return f"Gemini API failed after {retries} attempts."

# ==============================
# AI Utilities
# ==============================
def generate_summary(note_text):
    if len(note_text) > 3000:
        note_text = note_text[:3000] + " ...[truncated]"
    prompt = f"Summarize this note into concise points:\n{note_text}"
    return gemini_generate(prompt)

def generate_notes(topic):
    prompt = f"Generate detailed notes on the topic: {topic}"
    return gemini_generate(prompt)

# ==============================
# AI Assistant Route
# ==============================
@ai_bp.route("/assistant", methods=["GET", "POST"])
@login_required
def assistant():
    if request.is_json:
        data = request.get_json()
        content = data.get("content", "")
        action = data.get("action", "summarize")

        try:
            ai_response = generate_summary(content) if action == "summarize" else generate_notes(content)
        except Exception as e:
            ai_response = f"Error: {e}"

        return jsonify({"response": ai_response})

    # Fetch notes from Supabase
    resp = supabase.table("notes").select("*").eq("user_id", current_user.id).execute()
    notes_data = resp.data if resp.data else []
    notes = [Note.from_dict(n) for n in notes_data]

    ai_response = None

    if request.method == "POST":
        note_id = request.form.get("note_id")
        prompt = request.form.get("prompt", "")

        if note_id:
            note_resp = supabase.table("notes").select("*").eq("id", note_id).eq("user_id", current_user.id).execute()
            note_data = note_resp.data[0] if note_resp.data else None
            if note_data:
                prompt = f"{note_data.get('encrypted_content', '')}\n\nUser Query: {prompt}"

        try:
            ai_response = generate_summary(prompt) if "summarize" in prompt.lower() else generate_notes(prompt)
        except Exception as e:
            ai_response = f"Error: {e}"

    return render_template("ai_assistant.html", user=current_user, notes=notes, ai_response=ai_response)

# ==============================
# Save AI Note Route
# ==============================
@ai_bp.route("/save-ai-note", methods=["POST"])
@login_required
def save_ai_note():
    title = request.form.get("title")
    content = request.form.get("content")

    if not title or not content:
        flash("Title and content are required to save the note.", "error")
        return redirect(url_for("notes.dashboard"))

    supabase.table("notes").insert({
        "user_id": current_user.id,
        "title": title,
        "encrypted_content": content,
        "encryption_type": "AES",
        "pin_hash": "0000",
        "timestamp": datetime.utcnow().isoformat()
    }).execute()

    flash("AI-generated note saved successfully!", "success")
    return redirect(url_for("notes.dashboard"))
