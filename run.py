from securanote import create_app
from flask import redirect, send_file, current_app
from securanote.utils import decrypt_video_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os

app = create_app()

# Set up rate limiter
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["100 per hour"]
)

@app.route("/")
def index():
    return redirect("/login")

@app.route("/video")
def serve_chacha_video():
    try:
        decrypted_data = decrypt_video_file("securanote/static/secure/encrypted_video.txt")
        temp_folder = os.path.join(current_app.root_path, 'static', 'temp')
        os.makedirs(temp_folder, exist_ok=True)

        output_path = os.path.join(temp_folder, "video.mp4")
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)

        return send_file(output_path, mimetype='video/mp4')
    except Exception as e:
        return f"Error: {e}", 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)
