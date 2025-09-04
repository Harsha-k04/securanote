import os
import random
from datetime import datetime
from flask import Blueprint, request, render_template, jsonify, redirect, url_for, flash
from flask_login import login_required, current_user
from dotenv import load_dotenv
import requests
from securanote.models import Note  # Keep this for type/structure if needed
from securanote import supabase  # Make sure your Supabase client is imported here

load_dotenv()

# ==============================
# Blueprint
# ==============================
ai_bp = Blueprint("ai", __name__, url_prefix="/ai")

# ==============================
# Grok API Setup
# ==============================
GROK_API_KEY = os.getenv("GROK_API_KEY")
GROK_API_URL = "https://api.grok.ai/v1/chat"  # Replace with actual endpoint if different

def grok_generate(prompt, model="grok-4", max_tokens=500):
    headers = {
        "Authorization": f"Bearer {GROK_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens
    }

    try:
        response = requests.post(GROK_API_URL, json=payload, headers=headers)
        if response.status_code == 200:
            data = response.json()
            return data["choices"][0]["message"]["content"].strip()
        else:
            return f"Grok API Error {response.status_code}: {response.text}"
    except Exception as e:
        return f"Grok API Exception: {e}"

# ==============================
# AI Utilities
# ==============================
def generate_summary(note_text):
    """Generate a concise summary of a note using Grok"""
    if len(note_text) > 3000:
        note_text = note_text[:3000] + " ...[truncated]"
    prompt = f"Summarize this note into concise points:\n{note_text}"
    return grok_generate(prompt, max_tokens=500)

def generate_notes(topic):
    """Generate notes based on a topic using Grok"""
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

    # Save AI-generated note to Supabase
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
