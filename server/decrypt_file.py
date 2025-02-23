import sys
import os
import tarfile
from Crypto.Cipher import AES

AES_KEY = b"this_is_a_32byte_key_for_aes_123"  # Exactly 32 bytes
AES_BLOCK_SIZE = 16

def unpad(data):
    """Remove PKCS7 Padding"""
    pad_len = data[-1]
    return data[:-pad_len]

def decrypt_file(encrypted_file, session_id):
    """Decrypt a stored encrypted file manually when all chunks are received."""
    if not os.path.exists(encrypted_file):
        print(f"[-] Error: File {encrypted_file} not found!")
        return

    print(f"[+] Decrypting {encrypted_file}...")

    with open(encrypted_file, "rb") as f:
        iv = f.read(16)  # Read IV (first 16 bytes)
        ciphertext = f.read()  # Remaining encrypted data

    # Verify ciphertext length
    if len(ciphertext) % AES_BLOCK_SIZE != 0:
        print(f"[-] ERROR: Ciphertext length ({len(ciphertext)} bytes) is NOT a multiple of {AES_BLOCK_SIZE}!")
        print(f"[!] The file is likely corrupted or missing data.")
        return

    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext))

    decrypted_tar = f"{session_id}_received.tar.gz"
    with open(decrypted_tar, "wb") as f:
        f.write(decrypted_data)

    print(f"[+] Decrypted tar file saved as {decrypted_tar}")
    print(f"[!] To extract manually, run:")
    print(f"    tar -xzf {decrypted_tar} -C extracted_data/")



if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python decrypt_file.py <encrypted_file_path> <session_id>")
        sys.exit(1)

    encrypted_file_path = sys.argv[1]
    session_id = sys.argv[2]

    decrypt_file(encrypted_file_path, session_id)
