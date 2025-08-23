import os
from flask import Blueprint, request, render_template, jsonify, redirect, url_for, flash
from flask_login import login_required, current_user
from securanote.models import Note
from securanote import db
from openai import OpenAI

# ==============================
# Blueprint
# ==============================
ai_bp = Blueprint("ai", __name__, url_prefix="/ai")

# ==============================
# OpenAI Client
# ==============================
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

# ==============================
# AI Utilities
# ==============================
def local_ai_generate(prompt):
    """Fallback AI generation (local placeholder)"""
    return f"Local AI response: {prompt[:100]}..."

def openai_generate(prompt, max_tokens=300):
    """Generate text using OpenAI API"""
    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        print(f"OpenAI API failed: {e}")
        return local_ai_generate(prompt)

def generate_summary(note_text):
    """Generate a concise summary of a note"""
    if len(note_text) > 3000:
        note_text = note_text[:3000] + " ...[truncated]"
    prompt = f"Summarize this note into concise points:\n{note_text}"
    return openai_generate(prompt)

def generate_notes(topic):
    """Generate notes based on a topic"""
    prompt = f"Generate notes on the topic: {topic}"
    return openai_generate(prompt)

# ==============================
# AI Assistant Route
# ==============================
@ai_bp.route("/assistant", methods=["GET", "POST"])
@login_required
def assistant():
    notes = Note.query.filter_by(user_id=current_user.id).all()
    ai_response = None

    if request.method == "POST":
        note_id = request.form.get("note_id")
        prompt = request.form.get("prompt", "")

        # If user selected a note, prepend its content
        if note_id:
            note = Note.query.filter_by(id=note_id, user_id=current_user.id).first()
            if note:
                prompt = f"{note.encrypted_content}\n\nUser Query: {prompt}"

        # Call AI
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
        return redirect(url_for("ai.assistant"))

    # Save AI response as a note (encryption placeholder)
    new_note = Note(
        user_id=current_user.id,
        title=title,
        encrypted_content=content,
        encryption_type="AES",  # default encryption
        pin_hash="0000"  # placeholder PIN
    )
    db.session.add(new_note)
    db.session.commit()

    flash("AI-generated note saved successfully!", "success")
    return redirect(url_for("ai.assistant"))
