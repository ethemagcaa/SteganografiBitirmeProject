import base64
from io import BytesIO
from PIL import Image
from stegano import lsb
from flask import Flask, request, jsonify, send_file, render_template, session
import os
import cv2
import numpy as np
from extractcode import hide_image, blend_images, get_encryption_key, \
    extract_image  # extractcode.py içindeki fonksiyonları import et
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from werkzeug.utils import secure_filename
from extractcode import extract_image  # kendi fonksiyonun
app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
OUTPUT_FOLDER = "encrypted"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(OUTPUT_FOLDER, exist_ok=True)

def save_uploaded_file(file, filename):
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)
    return filepath

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/upload", methods=["POST"])
def upload_images():
    if "main_image" not in request.files or "secret_image" not in request.files:
        return jsonify({"success": False, "message": "Lütfen ana ve gizli resimleri yükleyin!"})

    main_image_file = request.files["main_image"]
    secret_image_file = request.files["secret_image"]
    algorithm = request.form.get("algorithm")
    user_key = request.form.get("user_key")

    if not user_key:
        return jsonify({"success": False, "message": "Şifre girilmelidir!"})

    if algorithm not in ["AES", "DES", "Blowfish"]:
        return jsonify({"success": False, "message": "Geçersiz algoritma seçimi!"})

    try:
        key = get_encryption_key(algorithm, user_key)  # Şifre oluşturmayı dene
    except ValueError as e:  # Eğer hata alırsak kullanıcıya JSON olarak dön
        return jsonify({"success": False, "message": str(e)})

    main_image_path = save_uploaded_file(main_image_file, "main_image.jpg")
    secret_image_path = save_uploaded_file(secret_image_file, "secret_image.jpg")

    main_image = cv2.imread(main_image_path)
    secret_image = cv2.imread(secret_image_path, cv2.IMREAD_GRAYSCALE)

    main_h, main_w, _ = main_image.shape
    secret_h, secret_w = secret_image.shape

    if secret_h > main_h or secret_w > main_w:
        return jsonify({
            "success": False,
            "message": f"Gizli resim çok büyük! Ana resmin boyutu: {main_w}x{main_h}, gizli resmin boyutu: {secret_w}x{secret_h}"
        })

    try:
        hidden_image = hide_image(main_image, secret_image, key, algorithm)
        hidden_image_path = os.path.join(OUTPUT_FOLDER, f"hidden_image_{algorithm}.jpg")
        cv2.imwrite(hidden_image_path, hidden_image)

        hidden_image2 = blend_images(hidden_image, secret_image, alpha=0.3)
        hidden_image2_path = os.path.join(OUTPUT_FOLDER, f"hidden_image2_{algorithm}.jpg")
        cv2.imwrite(hidden_image2_path, hidden_image2)

        return jsonify({"success": True, "message": f"Resimler {algorithm} ile başarıyla işlendi.", "algorithm": algorithm})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)})

def decrypt_aes(cipher_text, key):
    cipher = Cipher(algorithms.AES(key.encode()), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(cipher_text) + decryptor.finalize()

def decode_steganography(file, password):
    try:
        # Resmi aç
        image = Image.open(file)

        # LSB kullanarak gizli veriyi çıkar
        hidden_data = lsb.reveal(image)

        if hidden_data is None or not hidden_data.startswith(password):
            return None  # Eğer şifre yanlışsa veya veri yoksa hata ver

        # Şifreyi çıkar ve sadece gizli resmi al
        hidden_data = hidden_data[len(password):]

        # Base64 olarak decode et
        hidden_image_data = base64.b64decode(hidden_data)

        # Byte dizisini PIL Image olarak aç
        hidden_image = Image.open(BytesIO(hidden_image_data))

        # Yeni base64 formatına çevir
        buffered = BytesIO()
        hidden_image.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()

        return img_str
    except Exception:
        return None  # Hata olursa None döndür

@app.route("/extract", methods=["GET", "POST"])
def extract_hidden_image():
    if request.method == "GET":
        return render_template("extract.html")

    file = request.files.get("image")
    password = request.form.get("password")

    if not file:
        return jsonify({"error": "❌ Dosya yüklenmedi!"}), 400
    if not password:
        return jsonify({"error": "❌ Şifre girilmedi!"}), 400

    try:
        filename = secure_filename(file.filename)
        uploaded_path = os.path.join(UPLOAD_FOLDER, filename)
        file.save(uploaded_path)

        # Resmi oku
        hidden_image = cv2.imread(uploaded_path)

        # Şifre uzunluğuna göre algoritmayı tahmin et (bu kısmı daha sonra geliştirebilirsin)
        if len(password) == 8:
            algorithm = "DES"
        elif len(password) == 16:
            algorithm = "AES"  # veya Blowfish
        else:
            return jsonify({"error": "❌ Şifre uzunluğu geçersiz!"}), 400

        key = get_encryption_key(algorithm, password)

        # Gizli resmin çözülmüş hali
        # Not: Shape bilgisi tahmini olarak verilmeli veya dosyaya gömülmelidir. Şimdilik 256x256 varsayıyoruz.
        shape = (256, 256)  # Bu, gömdüğün gizli resmin orijinal boyutu olmalı!
        extracted = extract_image(hidden_image, key, algorithm)

        # Kaydet ve gönder
        output_path = os.path.join("static", "extracted_image.jpg")
        cv2.imwrite(output_path, extracted)

        return send_file(output_path, mimetype="image/jpeg", as_attachment=True, download_name="extracted_image.jpg")

    except Exception as e:
        print("Hata:", str(e))
        return jsonify({"error": "❌ Çıkarma işlemi sırasında hata oluştu!"}), 500
@app.route("/verify_key", methods=["POST"])
def verify_key():
    data = request.get_json()
    entered_key = data.get("key")

    # Daha önce kaydedilen şifreyi al
    stored_key = session.get("encryption_key")

    if stored_key and entered_key == stored_key:
        return jsonify({"success": True})  # Şifre doğru
    else:
        return jsonify({"success": False})  # Şifre yanlış

@app.route("/download/<filename>", methods=["GET"])
def download_file(filename):
    file_path = os.path.join(OUTPUT_FOLDER, filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    return jsonify({"success": False, "message": "Dosya bulunamadı!"})

if __name__ == "__main__":
    app.run(debug=True)