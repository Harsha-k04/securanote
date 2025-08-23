import os
import openai

# Optional: local AI placeholder
def local_ai_generate(prompt):
    # Placeholder: replace with local AI model inference if available
    return f"Local AI response: {prompt[:100]}..."

# OpenAI API integration
openai.api_key = os.getenv("OPENAI_API_KEY")

def openai_generate(prompt, max_tokens=300):
    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo", 
        messages=[{"role": "user", "content": prompt}],
        max_tokens=max_tokens
    )
    return response.choices[0].message.content.strip()

# Handle long notes safely
def safe_send_to_ai(ai_function):
    try:
        result = ai_function()
    except Exception as e:
        # fallback to local AI if OpenAI fails
        print(f"AI API failed: {e}")
        result = local_ai_generate("Fallback response")
    return result

# Core AI functions
def generate_summary(note_text):
    # Split note if too long
    if len(note_text) > 3000:
        note_text = note_text[:3000] + " ...[truncated]"
    prompt = f"Summarize this note into concise points:\n{note_text}"
    return openai_generate(prompt)

def generate_notes(topic):
    prompt = f"Generate notes on the topic: {topic}"
    return openai_generate(prompt)
