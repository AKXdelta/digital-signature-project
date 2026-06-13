from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from crypto.keys import load_private_key
import os

SIGNATURES_DIR = os.path.join(os.path.dirname(__file__), "..", "signatures")
os.makedirs(SIGNATURES_DIR, exist_ok=True)


def sign_content(content: str) -> bytes:
    """
    Sign normalized content using RSA-PSS.
    Returns signature as bytes.
    """
    try:
        private_key = load_private_key()
    except (FileNotFoundError, RuntimeError) as e:
        raise RuntimeError(f"Cannot sign: {e}")

    try:
        signature = private_key.sign(
            content.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    except Exception as e:
        raise RuntimeError(f"Failed to sign content: {e}")


def save_signature(signature: bytes, original_file_path: str) -> str:
    """
    Save signature in signatures/ folder as file_name.sig
    """
    try:
        filename = os.path.basename(original_file_path)
        sig_path = os.path.join(SIGNATURES_DIR, filename + ".sig")

        with open(sig_path, "wb") as f:
            f.write(signature)

        print(f"✅ Signature saved → {sig_path}")
        return sig_path
    except (IOError, OSError) as e:
        raise RuntimeError(f"Failed to save signature: {e}")


def sign_document(content: str, original_file_path: str) -> str:
    """
    Sign content and save signature file.
    """
    try:
        signature = sign_content(content)
        sig_path = save_signature(signature, original_file_path)
        return sig_path
    except RuntimeError as e:
        print(f"❌ Failed to sign document: {e}")
        raise