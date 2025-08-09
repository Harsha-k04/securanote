import os
import time
import pandas as pd

# Import your encryption functions from utils.py
from utils import encrypt_note_content, encrypt_chacha, encrypt_blowfish, blowfish_key

# Generate a random AES key for testing (32 bytes = AES-256)
aes_key = os.urandom(32)

# Folder containing test files
TEST_FOLDER = "test_files"  # Change this to your folder path

results = []

# Iterate over all files in the folder
for filename in os.listdir(TEST_FOLDER):
    file_path = os.path.join(TEST_FOLDER, filename)
    
    if not os.path.isfile(file_path):
        continue  # Skip non-files
    
    with open(file_path, "rb") as f:
        data = f.read()

    size_mb = len(data) / (1024 * 1024)  # File size in MB

    # AES-256 Encryption Timing
    try:
        start = time.perf_counter()
        encrypt_note_content(data.decode(errors="ignore"), aes_key)
        end = time.perf_counter()
        elapsed = end - start
        throughput = size_mb / elapsed if elapsed > 0 else 0
        results.append({
            "File": filename,
            "Algorithm": "AES-256",
            "FileSize_MB": size_mb,
            "EncryptionTime_s": elapsed,
            "Throughput_MBps": throughput
        })
    except Exception as e:
        print(f"[AES ERROR] {filename}: {e}")

    # ChaCha20 Encryption Timing
    try:
        start = time.perf_counter()
        encrypt_chacha(data)
        end = time.perf_counter()
        elapsed = end - start
        throughput = size_mb / elapsed if elapsed > 0 else 0
        results.append({
            "File": filename,
            "Algorithm": "ChaCha20",
            "FileSize_MB": size_mb,
            "EncryptionTime_s": elapsed,
            "Throughput_MBps": throughput
        })
    except Exception as e:
        print(f"[ChaCha ERROR] {filename}: {e}")

    # Blowfish Encryption Timing
    try:
        start = time.perf_counter()
        encrypt_blowfish(data, blowfish_key)
        end = time.perf_counter()
        elapsed = end - start
        throughput = size_mb / elapsed if elapsed > 0 else 0
        results.append({
            "File": filename,
            "Algorithm": "Blowfish",
            "FileSize_MB": size_mb,
            "EncryptionTime_s": elapsed,
            "Throughput_MBps": throughput
        })
    except Exception as e:
        print(f"[Blowfish ERROR] {filename}: {e}")

# Save results to CSV
df = pd.DataFrame(results)
df.to_csv("encryption_benchmark.csv", index=False)

# Summary Table
summary = df.groupby("Algorithm").agg({
    "EncryptionTime_s": "mean",
    "Throughput_MBps": "mean"
}).reset_index()

print("✅ Benchmarking complete! Results saved to encryption_benchmark.csv\n")
print("📊 Summary Table (averages across files):")
print(summary)
