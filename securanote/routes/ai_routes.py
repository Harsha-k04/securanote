import os
import random
from datetime import datetime
from flask import Blueprint, request, render_template, jsonify, redirect, url_for, flash
from flask_login import login_required, current_user
from dotenv import load_dotenv
import requests
import certifi
import ssl
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
import time
import logging

from securanote.models import Note
from securanote import supabase

load_dotenv()

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
# Grok API Setup
# ==============================
GROK_API_KEY = os.environ.get("GROK_API_KEY")
print(GROK_API_KEY)
GROK_API_URL = "https://api.x.ai/v1/chat/completions"

# TLS Adapter to enforce modern TLS versions
class TLSAdapter(HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Disable TLS 1.0 & 1.1
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)

# Create a requests session with TLS fix
session = requests.Session()
session.mount("https://", TLSAdapter())

# ==============================
# Grok Generate with Retry
# ==============================
def grok_generate(prompt, model="grok-4", max_tokens=500, retries=3, backoff=2):
    headers = {
        "Authorization": f"Bearer {GROK_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens
    }

    attempt = 0
    while attempt < retries:
        try:
            response = session.post(
                GROK_API_URL,
                json=payload,
                headers=headers,
                verify=certifi.where()
            )
            if response.status_code == 200:
                data = response.json()
                return data["choices"][0]["message"]["content"].strip()
            else:
                logger.error(f"Grok API Error {response.status_code}: {response.text}")
                return f"Grok API Error {response.status_code}: {response.text}"

        except requests.exceptions.SSLError as ssl_err:
            attempt += 1
            logger.warning(f"SSL Error (attempt {attempt}/{retries}): {ssl_err}")
            if attempt >= retries:
                return f"SSL Error after {attempt} attempts: {ssl_err}"
            time.sleep(backoff ** attempt)

        except requests.exceptions.RequestException as req_err:
            attempt += 1
            logger.warning(f"Request Error (attempt {attempt}/{retries}): {req_err}")
            if attempt >= retries:
                return f"Request Error after {attempt} attempts: {req_err}"
            time.sleep(backoff ** attempt)

        except Exception as e:
            logger.error(f"Grok API Exception: {e}")
            return f"Grok API Exception: {e}"

# ==============================
# AI Utilities
# ==============================
def generate_summary(note_text):
    if len(note_text) > 3000:
        note_text = note_text[:3000] + " ...[truncated]"
    prompt = f"Summarize this note into concise points:\n{note_text}"
    return grok_generate(prompt, max_tokens=500)

def generate_notes(topic):
    prompt = f"Generate detailed notes on the topic: {topic}"
    return grok_generate(prompt, max_tokens=500)

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
            if action == "summarize":
                ai_response = generate_summary(content)
            else:
                ai_response = generate_notes(content)
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
            if "summarize" in prompt.lower():
                ai_response = generate_summary(prompt)
            else:
                ai_response = generate_notes(prompt)
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
