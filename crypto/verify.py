from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from crypto.keys import load_public_key
import os
from formats.json_handler import read_json, json_to_string
from formats.pdf_handler import read_pdf
from formats.txt_handler import read_txt


def verify_content(content: str, signature: bytes) -> bool:
    """
    Verify RSA-PSS signature.
    Returns True if valid, False otherwise.
    """
    try:
        public_key = load_public_key()
    except (FileNotFoundError, RuntimeError) as e:
        print(f"❌ Cannot verify: {e}")
        return False

    try:
        public_key.verify(
            signature,
            content.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        print("✅ Signature VALID")
        return True

    except InvalidSignature:
        print("❌ Signature INVALID")
        return False
    except Exception as e:
        print(f"❌ Error during verification: {e}")
        return False


def verify_file(filepath, sig_path, key_path=None):
    """
    Verify a file's signature.
    Supports: PDF, JSON, TXT
    Returns a result dictionary.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    
    if not os.path.exists(sig_path):
        raise FileNotFoundError(f"Signature file not found: {sig_path}")
    
    # Read the signature
    with open(sig_path, "rb") as f:
        signature = f.read()
    
    # Read content based on file type
    ext = os.path.splitext(filepath)[1].lower()
    
    if ext == ".pdf":
        content = read_pdf(filepath)
    elif ext == ".json":
        data = read_json(filepath)
        content = json_to_string(data)
    elif ext == ".txt":
        content = read_txt(filepath)
    else:
        raise ValueError(f"Unsupported file format: {ext}")
    
    # Verify the signature
    is_valid = verify_content(content, signature)
    
    return {
        "valid": is_valid,
        "status": "VALID" if is_valid else "INVALID",
        "algo": "RSA-PSS",
        "expired": False
    }