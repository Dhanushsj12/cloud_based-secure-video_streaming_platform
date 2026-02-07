from flask import Flask, render_template, request, redirect, url_for, session, Response
import os
import cloudinary
import cloudinary.uploader
import cloudinary.api
import cloudinary.utils
import requests
import base64
import gzip
import tempfile
import atexit
import cv2
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from io import BytesIO

app = Flask(__name__)
app.secret_key = "supersecretkey123"

# ---------------- USERS ----------------
users = {
    "admin": {"password": "admin123", "role": "admin"},
    "subscriber": {"password": "sub123", "role": "subscriber"},
    "viewer": {"password": "view123", "role": "viewer"}
}

# ---------------- AES CONFIG ----------------
key = base64.b64decode("VGhpc0lzQTMyQnl0ZUxvbmdTZWNyZXRLZXkxMjM0NTY=")
iv = base64.b64decode("VGhpc0lzQW5JVjEyMzQ1Ng==")

# ---------------- CLOUDINARY ----------------
cloudinary.config(
    cloud_name="djrjzfcxe",
    api_key="616842116678695",
    api_secret="Cyz2W2v_uJjUKHniT4hJw_MeYqY"
)

# ---------------- ENCRYPT / DECRYPT ----------------
def compress_and_encrypt(input_file, output_file):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with tempfile.NamedTemporaryFile(delete=False) as temp:
        with gzip.open(temp.name, "wb") as gz:
            with open(input_file, "rb") as f:
                gz.write(f.read())

        with open(temp.name, "rb") as f:
            compressed = f.read()

    encrypted = encryptor.update(compressed) + encryptor.finalize()

    with open(output_file, "wb") as f:
        f.write(iv + encrypted)

    os.remove(temp.name)
    return output_file


def decrypt_and_decompress(data):
    file_iv = data[:16]
    encrypted = data[16:]

    cipher = Cipher(algorithms.AES(key), modes.CFB(file_iv), backend=default_backend())
    decryptor = cipher.decryptor()

    compressed = decryptor.update(encrypted) + decryptor.finalize()

    with gzip.GzipFile(fileobj=BytesIO(compressed), mode="rb") as gz:
        return gz.read()

# ---------------- ROUTES ----------------
@app.route("/")
def home():
    return redirect(url_for("login"))

# ---------------- LOGIN ----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    if request.method == "POST":
        user = users.get(request.form.get("username"))
        if user and user["password"] == request.form.get("password"):
            session["authenticated"] = True
            session["user"] = request.form["username"]
            session["role"] = user["role"]
            return redirect(url_for("dashboard"))
        error = "Invalid credentials"

    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
def dashboard():
    if not session.get("authenticated"):
        return redirect(url_for("login"))

    uploaded = cloudinary.api.resources(resource_type="raw", type="upload", tags=True)
    thumbnails = cloudinary.api.resources(type="upload", prefix="thumbnails/")

    thumb_map = {}
    for t in thumbnails.get("resources", []):
        name = os.path.basename(t["public_id"])
        thumb_map[name] = t["secure_url"]

    videos = uploaded.get("resources", [])
    for v in videos:
        base = os.path.basename(v["public_id"]).replace(".gz", "")
        v["display_name"] = base
        v["thumbnail_url"] = thumb_map.get(base, "")

    return render_template("dashboard.html", videos=videos, role=session.get("role"))

# ---------------- UPLOAD ----------------
@app.route("/upload", methods=["GET", "POST"])
def upload_video():
    if not session.get("authenticated") or session.get("role") != "admin":
        return redirect(url_for("login"))

    if request.method == "POST":

        # ✅ SAFE CHECKS (PREVENTS BadRequestKeyError)
        if "video" not in request.files or "thumbnail" not in request.files:
            return "Video or Thumbnail missing", 400

        video = request.files.get("video")
        thumb = request.files.get("thumbnail")

        if video.filename == "" or thumb.filename == "":
            return "Select both video and thumbnail", 400

        raw_path = os.path.join(tempfile.gettempdir(), video.filename)
        video.save(raw_path)

        thumb_name = os.path.splitext(video.filename)[0]
        thumb_path = os.path.join(tempfile.gettempdir(), thumb_name + ".jpg")
        thumb.save(thumb_path)

        cloudinary.uploader.upload(
            thumb_path,
            public_id=f"thumbnails/{thumb_name}",
            overwrite=True
        )
        os.remove(thumb_path)

        encrypted_path = raw_path + ".enc"
        compress_and_encrypt(raw_path, encrypted_path)

        cloudinary.uploader.upload(
            encrypted_path,
            resource_type="raw",
            public_id=thumb_name + ".gz",
            tags=["video_upload"],
            access_mode="public"
        )

        os.remove(raw_path)
        os.remove(encrypted_path)

        return render_template("success.html", filename=video.filename)

    uploaded = cloudinary.api.resources(resource_type="raw", type="upload", tags=True)
    return render_template("upload.html", videos=uploaded.get("resources", []), role=session.get("role"))

# ---------------- DELETE ----------------
@app.route("/delete/<public_id>", methods=["POST"])
def delete_video(public_id):
    if session.get("role") != "admin":
        return "Unauthorized", 403

    cloudinary.uploader.destroy(public_id, resource_type="raw", type="upload")
    cloudinary.uploader.destroy("thumbnails/" + public_id.replace(".gz", ""), type="upload")
    return redirect(url_for("dashboard"))

# ---------------- STREAM ----------------
@app.route("/stream/<public_id>")
def stream_video(public_id):
    if session.get("role") not in ["admin", "subscriber"]:
        return "Unauthorized", 403

    url, _ = cloudinary.utils.cloudinary_url(
        public_id,
        resource_type="raw",
        type="upload",
        secure=True
    )

    r = requests.get(url)
    data = decrypt_and_decompress(r.content)

    fd, path = tempfile.mkstemp(suffix=".mp4")
    with os.fdopen(fd, "wb") as f:
        f.write(data)

    cap = cv2.VideoCapture(path)
    user = session.get("user", "anonymous")

    def generate():
        while cap.isOpened():
            ok, frame = cap.read()
            if not ok:
                break
            cv2.putText(frame, f"@{user}", (10, frame.shape[0]-10),
                        cv2.FONT_HERSHEY_SIMPLEX, 1, (255,255,255), 2)
            _, buf = cv2.imencode(".jpg", frame)
            yield (b"--frame\r\nContent-Type: image/jpeg\r\n\r\n" +
                   buf.tobytes() + b"\r\n")

    return Response(generate(), mimetype="multipart/x-mixed-replace; boundary=frame")

@app.route("/stream_view/<public_id>")
def stream_view(public_id):
    if not session.get("authenticated"):
        return redirect(url_for("login"))
    return render_template("stream.html", public_id=public_id)

# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True, port=5001)
