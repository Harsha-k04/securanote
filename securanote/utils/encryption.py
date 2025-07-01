from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import base64

# Key for AES & ChaCha (32 bytes for AES-256 and ChaCha20)
ENCRYPTION_KEY = os.environ.get("VAULT_ENCRYPTION_KEY", os.urandom(32))  # Use .env in production

def encrypt_aes(plaintext):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(ENCRYPTION_KEY), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return base64.b64encode(iv + ciphertext).decode()

def encrypt_chacha(plaintext):
    nonce = os.urandom(16)
    algorithm = algorithms.ChaCha20(ENCRYPTION_KEY, nonce)
    cipher = Cipher(algorithm, mode=None, backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode())
    return base64.b64encode(nonce + ciphertext).decode()
