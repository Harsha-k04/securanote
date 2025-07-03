import os
import base64
import ssl
from dotenv import load_dotenv
import certifi
import boto3
from botocore.exceptions import NoCredentialsError
from botocore.config import Config
import botocore.session
import urllib3.util.ssl_

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from Crypto.Cipher import AES, ChaCha20

# ----------------------------- #
# SSL Fix for CERTIFICATE_VERIFY_FAILED
# ----------------------------- #
os.environ['SSL_CERT_FILE'] = certifi.where()
ssl._create_default_https_context = ssl.create_default_context

# Ensure urllib3 and botocore use certifi as well
urllib3.util.ssl_.DEFAULT_CA_BUNDLE_PATH = certifi.where()
session = botocore.session.get_session()
session.set_config_variable('ca_bundle', certifi.where())

print("Using certifi bundle from:", certifi.where())

# ----------------------------- #
# Load .env Variables
# ----------------------------- #
load_dotenv()

# ----------------------------- #
# Initialize S3 Client Securely
# ----------------------------- #
s3_client = boto3.client(
    's3',
    region_name=os.getenv("AWS_S3_REGION", "ap-south-1"),
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    #verify=certifi.where(),
    config=Config(retries={'max_attempts': 3}),
    verify=False
)

# ----------------------------- #
# Fernet AES Key Setup
# ----------------------------- #
fernet_key = os.getenv("FERNET_KEY")
if not fernet_key:
    raise EnvironmentError("FERNET_KEY not found in .env file")
fernet = Fernet(fernet_key.encode())

# ----------------------------- #
# ChaCha20 Key Setup
# ----------------------------- #
CHACHA_KEY = os.getenv("CHACHA_KEY")
if not CHACHA_KEY:
    raise EnvironmentError("CHACHA_KEY not found in .env file")
try:
    chacha_key = base64.urlsafe_b64decode(CHACHA_KEY + '=' * (-len(CHACHA_KEY) % 4))
except Exception as e:
    raise ValueError("Invalid CHACHA_KEY format. Must be base64-encoded 32-byte string.") from e

# ----------------------------- #
# Encryption/Decryption Functions
# ----------------------------- #
def encrypt_content(content: str, encryption_type: str) -> str:
    if encryption_type == 'AES':
        return fernet.encrypt(content.encode()).decode()
    elif encryption_type == 'ChaCha':
        return encrypt_chacha(content.encode())
    else:
        raise ValueError("Unsupported encryption type.")

def encrypt_video_file(input_path: str, output_path: str):
    with open(input_path, 'rb') as f:
        file_data = f.read()
    encrypted = encrypt_chacha(file_data)
    with open(output_path, 'w') as f:
        f.write(encrypted)

def decrypt_content(encrypted_content: str, encryption_type: str) -> str:
    if encryption_type == 'AES':
        return fernet.decrypt(encrypted_content.encode()).decode()
    elif encryption_type == 'ChaCha':
        return decrypt_chacha(encrypted_content)
    else:
        raise ValueError("Unsupported encryption type.")

def decrypt_video_file(input_path: str) -> bytes:
    with open(input_path, 'r') as f:
        encrypted = f.read()
    return decrypt_chacha_bytes(encrypted)

def encrypt_chacha(plain_data: bytes) -> str:
    nonce = os.urandom(12)
    chacha = ChaCha20Poly1305(chacha_key)
    ciphertext = chacha.encrypt(nonce, plain_data, None)
    return base64.urlsafe_b64encode(nonce + ciphertext).decode()

def encrypt_chacha_bytes(plain_data: bytes) -> bytes:
    nonce = os.urandom(12)
    chacha = ChaCha20Poly1305(chacha_key)
    return nonce + chacha.encrypt(nonce, plain_data, None)

def decrypt_chacha(enc_data: str) -> str:
    decrypted_bytes = decrypt_chacha_bytes(enc_data)
    try:
        return decrypted_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError("Decrypted data is not valid UTF-8 text. Use decrypt_chacha_bytes() for binary content.")

def decrypt_chacha_bytes(enc_data) -> bytes:
    try:
        if isinstance(enc_data, str):
            enc_data = enc_data.encode('utf-8')
        enc_data += b'=' * (-len(enc_data) % 4)
        encrypted = base64.urlsafe_b64decode(enc_data)
        nonce = encrypted[:12]
        ciphertext = encrypted[12:]
        chacha = ChaCha20Poly1305(chacha_key)
        return chacha.decrypt(nonce, ciphertext, None)
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")

def encrypt_note_content(content, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(content.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def decrypt_note_content(encrypted_content, key):
    data = base64.b64decode(encrypted_content.encode())
    nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# ----------------------------- #
# S3 File Operations
# ----------------------------- #
def upload_file_to_s3(encrypted_data: bytes, filename: str) -> bool:
    try:
        s3_client.put_object(
            Bucket=os.getenv("AWS_S3_BUCKET"),
            Key=filename,
            Body=encrypted_data
        )
        return True
    except NoCredentialsError:
        print("AWS credentials not found.")
        return False
    except Exception as e:
        print("Upload failed:", e)
        return False

def download_file_from_s3(filename: str) -> bytes:
    try:
        response = s3_client.get_object(
            Bucket=os.getenv("AWS_S3_BUCKET"),
            Key=filename
        )
        return response['Body'].read()
    except Exception as e:
        print("Download failed:", e)
        return None

def delete_file_from_s3(filename: str) -> bool:
    try:
        s3_client.delete_object(
            Bucket=os.getenv("AWS_S3_BUCKET"),
            Key=filename
        )
        return True
    except Exception as e:
        print("Delete failed:", e)
        return False

