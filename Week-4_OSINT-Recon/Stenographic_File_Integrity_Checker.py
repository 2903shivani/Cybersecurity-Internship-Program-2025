# qr_integrity_checker.py
# Proof of Concept - QR Code File Integrity Checker

import hashlib
import qrcode
import cv2

# 1. Hashing Function
def compute_hash(file_path):
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()

# 2. QR Code Generation
def generate_qr(file_path, qr_path):
    file_hash = compute_hash(file_path)
    qr_img = qrcode.make(file_hash)
    qr_img.save(qr_path)
    print(f"Successfully generated QR code of {file_path} hash as {qr_path}")

# 3. QR Code Decoding
def decode_qr(qr_path):
    detector = cv2.QRCodeDetector()
    data, _, _ = detector.detectAndDecode(cv2.imread(qr_path))
    return data if data else None

# 4. Verification
def verify_file(file_path, qr_path):
    current_hash = compute_hash(file_path)
    stored_hash = decode_qr(qr_path)

    if stored_hash is None:
        print("Failed to decode QR code!")
        return

    if current_hash == stored_hash:
        print(f"File integrity verified! {file_path} has not been changed.")
    else:
        print(f"File integrity check failed! {file_path} has been altered.")

# -----------------------------
# Example usage
# -----------------------------
if __name__ == "__main__":
    target_file = "report.pdf"
    qr_code_file = "report_qr.png"

    choice = input("Enter 'g' to generate QR or 'v' to verify: ").lower()

    if choice == 'g':
        generate_qr(target_file, qr_code_file)
    elif choice == 'v':
        verify_file(target_file, qr_code_file)
    else:
        print("Invalid option. Use 'g' for generate or 'v' for verify.")
