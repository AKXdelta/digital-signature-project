import hashlib
import os

def hash_content(content: str, algorithm: str = "sha256"):
    """Hash content using specified algorithm."""
    try:
        if algorithm.lower() == "sha256":
            return hashlib.sha256(
                content.encode("utf-8")
            ).hexdigest()
        elif algorithm.lower() == "sha3":
            return hashlib.sha3_256(
                content.encode("utf-8")
            ).hexdigest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    except Exception as e:
        raise ValueError(f"Hashing failed: {e}")

def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    """Hash raw bytes using specified algorithm."""
    try:
        if algorithm.lower() == "sha256":
            return hashlib.sha256(data).hexdigest()
        elif algorithm.lower() == "sha3":
            return hashlib.sha3_256(data).hexdigest()
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    except Exception as e:
        raise ValueError(f"Hashing failed: {e}")


def hash_file(filepath: str, algorithm: str = "sha256") -> str:
    """Hash any file using specified algorithm (SHA-256 or SHA-3)."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    try:
        with open(filepath, 'rb') as f:
            content = f.read()

        result = hash_bytes(content, algorithm=algorithm)
        algo_name = algorithm.upper()
        print(f"✅ [{algo_name}] {os.path.basename(filepath)} → {result}")
        return result
    except Exception as e:
        raise ValueError(f"Failed to hash file: {e}")