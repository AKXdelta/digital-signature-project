import hashlib
import os


def hash_bytes(data: bytes) -> str:
    """Hash raw bytes using SHA-256"""
    return hashlib.sha256(data).hexdigest()


def hash_file(filepath: str) -> str:
    """Hash any file (TXT, PDF, DOCX...) using SHA-256"""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    with open(filepath, 'rb') as f:
        content = f.read()

    result = hash_bytes(content)
    print(f"✅ [SHA-256] {os.path.basename(filepath)} → {result}")
    return result