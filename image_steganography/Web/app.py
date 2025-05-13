from flask import Flask, render_template, request, url_for
import cv2
import numpy as np
import os
import base64

app = Flask(__name__)
UPLOAD_FOLDER = "static/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Şifreleri algoritmaya göre belirleme
PASSWORDS = {
    "AES": "16byteslongkey!!",
    "DES": "12345678",
    "Blowfish": "16byteslongkeyss"
}

@app.route('/')
def index():
    return render_template('extract.html')

@app.route('/decode', methods=['POST'])
def decode():
    if 'file' not in request.files or request.files['file'].filename == '':
        return "No file uploaded", 400

    file = request.files['file']
    user_password = request.form['password']
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    # Dosya adına göre algoritmayı belirleme
    algorithm = next((algo for algo in PASSWORDS if algo in file.filename), None)
    if not algorithm:
        return "Invalid file format. Must contain AES, DES, or Blowfish in the filename", 400

    correct_password = PASSWORDS[algorithm]
    if user_password != correct_password:
        return "Incorrect password", 400

    hidden_image = extract_hidden_image(file_path)
    if hidden_image is None:
        return "No hidden image found", 400

    hidden_image_path = os.path.join(UPLOAD_FOLDER, "decoded.png")
    cv2.imwrite(hidden_image_path, hidden_image)

    return render_template('extract.html', hidden_image=url_for('static', filename='uploads/decoded.png'))

def extract_hidden_image(encrypted_image_path):
    try:
        img = cv2.imread(encrypted_image_path)
        if img is None:
            print("Dosya okunamadı: ", encrypted_image_path)
            return None

        # Tüm pikselleri binary olarak oku
        binary_data = "".join(format(byte, '08b') for row in img for pixel in row for byte in pixel)
        print("Binary data (first 100 bits):", binary_data[:100])

        start_marker = '11111111' * 3  # Başlangıç işareti (24 bit)
        start_index = binary_data.find(start_marker)
        if start_index == -1:
            print("Başlangıç işareti bulunamadı!")
            return None

        hidden_binary_data = binary_data[start_index + len(start_marker):]
        byte_list = [hidden_binary_data[i:i + 8] for i in range(0, len(hidden_binary_data), 8)]
        hidden_bytes = bytearray(int(byte, 2) for byte in byte_list if len(byte) == 8)

        print("Hidden binary data (first 50 bits):", hidden_binary_data[:50])
        with open("debug_hidden_bytes.bin", "wb") as f:
            f.write(hidden_bytes)
        print("Hidden bytes saved for debugging")

        try:
            hidden_bytes = base64.b64decode(hidden_bytes)  # Eğer base64 kodlanmışsa çöz
        except Exception as e:
            print("Base64 decoding error, continuing without decoding:", e)

        hidden_image_array = np.frombuffer(hidden_bytes, dtype=np.uint8)
        if hidden_image_array.size == 0:
            print("Extracted hidden image is empty!")
            return None

        hidden_img = cv2.imdecode(hidden_image_array, cv2.IMREAD_COLOR)
        return hidden_img
    except Exception as e:
        print("Error extracting hidden image:", e)
        return None

if __name__ == '__main__':
    app.run(debug=True)
