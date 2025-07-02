from securanote import create_app
from flask import redirect, Response
import os
from flask import send_file, current_app
from securanote.utils import decrypt_video_file

# 👇 Make sure to import this
from securanote.utils import decrypt_video_file  # update the path based on your structure

app = create_app()

@app.route("/")
def index():
    return redirect("/login")

# ✅ Route to serve decrypted ChaCha video
@app.route("/video")
def serve_chacha_video():
    try:
        # Decrypt video from .txt file
        decrypted_data = decrypt_video_file("securanote/static/secure/encrypted_video.txt")
        
        # Create temp folder if not exists
        temp_folder = os.path.join(current_app.root_path, 'static', 'temp')
        os.makedirs(temp_folder, exist_ok=True)
        
        # Save the decrypted video to static/temp/video.mp4
        output_path = os.path.join(temp_folder, "video.mp4")
        with open(output_path, 'wb') as f:
            f.write(decrypted_data)

        # Serve the decrypted file
        return send_file(output_path, mimetype='video/mp4')

    except Exception as e:
        return f"Error: {e}", 500

# 👇 Optional: Automatically open browser


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host="0.0.0.0", port=port)

