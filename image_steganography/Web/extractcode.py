import cv2
import numpy as np
from Crypto.Cipher import AES, DES, Blowfish
from Crypto.Util.Padding import pad, unpad
import base64


def get_encryption_key(algorithm, user_key):
    if user_key is None:
        raise ValueError("Şifre None olamaz!")  # Eğer şifre None ise, hata fırlat

    key_sizes = {
        "AES": 16,
        "DES": 8,
        "Blowfish": 16
    }

    key_size = key_sizes.get(algorithm, None)

    if key_size is None:
        raise ValueError("Geçersiz algoritma!")  # Hatalı algoritma ismi kontrolü

    user_key = user_key.encode()  # String şifreyi byte formatına çeviriyoruz.

    if len(user_key) != key_size:
        raise ValueError(f"Şifre {algorithm} için tam olarak {key_size} byte uzunluğunda olmalıdır!")

    return user_key


def get_cipher(algorithm, key, iv=None):
    if algorithm == 'AES':
        return AES.new(key, AES.MODE_CBC, iv) if iv else AES.new(key, AES.MODE_CBC), AES.block_size
    elif algorithm == 'DES':
        return DES.new(key[:8], DES.MODE_CBC, iv) if iv else DES.new(key[:8], DES.MODE_CBC), DES.block_size
    elif algorithm == 'Blowfish':
        return Blowfish.new(key[:16], Blowfish.MODE_CBC, iv) if iv else Blowfish.new(key[:16],
                                                                                     Blowfish.MODE_CBC), Blowfish.block_size
    else:
        raise ValueError("Unsupported algorithm")


def encrypt_image(secret_image, key, algorithm):
    cipher, block_size = get_cipher(algorithm, key)
    encrypted_data = cipher.encrypt(pad(secret_image.tobytes(), block_size))
    return cipher.iv + encrypted_data


def decrypt_image(encrypted_data, key, shape, algorithm):
    iv = encrypted_data[:16]
    cipher, block_size = get_cipher(algorithm, key, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data[16:]), block_size)
    return np.frombuffer(decrypted_data, dtype=np.uint8).reshape(shape)


def hide_image(main_image, secret_image, key, algorithm):
    encrypted_secret = encrypt_image(secret_image, key, algorithm)

    # shape bilgisi + şifreli veri
    shape_info = f"{secret_image.shape[0]},{secret_image.shape[1]}".encode().ljust(16, b'_')
    total_data = shape_info + encrypted_secret

    encoded_secret = base64.b64encode(total_data)
    hidden_image = main_image.copy()

    max_bytes = hidden_image.shape[0] * hidden_image.shape[1] * 3 // 8
    if len(encoded_secret) > max_bytes:
        raise ValueError("Gizli resim çok büyük!")

    binary_secret = ''.join(format(byte, '08b') for byte in encoded_secret)
    binary_secret += '1111111111111110'

    data_index = 0
    flat_image = hidden_image.flatten()
    for i in range(len(flat_image)):
        if data_index < len(binary_secret):
            flat_image[i] = (flat_image[i] & 254) | int(binary_secret[data_index])
            data_index += 1
        else:
            break

    return flat_image.reshape(hidden_image.shape)

def extract_image(hidden_image, key, algorithm):
    binary_secret = ''.join(map(str, (hidden_image.flatten() & 1)))
    end_marker = "1111111111111110"
    end_index = binary_secret.find(end_marker)

    if end_index == -1:
        raise ValueError("Gizli veri bulunamadı!")

    binary_secret = binary_secret[:end_index]
    encoded_secret = bytes(int(binary_secret[i:i + 8], 2) for i in range(0, len(binary_secret), 8))
    total_data = base64.b64decode(encoded_secret)

    # Shape bilgisi ilk 16 bayt
    shape_info = total_data[:16].decode().strip('_')
    h, w = map(int, shape_info.split(','))

    encrypted_data = total_data[16:]
    decrypted = decrypt_image(encrypted_data, key, (h, w), algorithm)
    return decrypted



def blend_images(main_image, secret_image, alpha=0.3, position=(50, 50)):
    overlay = main_image.copy()
    h, w = secret_image.shape[:2]
    x, y = position

    if x + w > main_image.shape[1] or y + h > main_image.shape[0]:
        raise ValueError("Gizli resmin konumu ana resmin sınırlarını aşıyor!")

    if len(secret_image.shape) == 2:
        secret_image = cv2.cvtColor(secret_image, cv2.COLOR_GRAY2BGR)

    roi = overlay[y:y + h, x:x + w]
    blended = cv2.addWeighted(roi, 1 - alpha, secret_image, alpha, 0)
    overlay[y:y + h, x:x + w] = blended
    return overlay


def main():
    algorithm = 'AES'
    user_password = input("Lütfen şifreyi girin: ")
    key = get_encryption_key(algorithm, user_password)

    if key is None:
        raise ValueError("Geçersiz şifreleme algoritması!")

    main_image = cv2.imread("../images/main_image.jpg")
    secret_image = cv2.imread("../images/secret_image.jpg", cv2.IMREAD_GRAYSCALE)

    print("Gizli resim şifreleniyor ve gömülüyor...")
    hidden_image = hide_image(main_image, secret_image, key, algorithm)

    output_path = "../encrypted/hidden_image.jpg"
    cv2.imwrite(output_path, hidden_image)
    print("Gömülen resim başarıyla kaydedildi.")

    hidden_image2 = blend_images(hidden_image, secret_image, alpha=0.3)
    output_path2 = "../encrypted/hidden_image2.jpg"
    cv2.imwrite(output_path2, hidden_image2)
    print("hidden_image2 başarıyla kaydedildi.")

    print("\nGömülü resimden veri çıkartılıyor...")
    extracted_image = extract_image(hidden_image, key, secret_image.shape, algorithm)

    extracted_path = "../encrypted/extracted_image.jpg"
    cv2.imwrite(extracted_path, extracted_image)
    print("Gizli resim başarıyla çıkarıldı ve kaydedildi.")


if __name__ == "__main__":
    main()
