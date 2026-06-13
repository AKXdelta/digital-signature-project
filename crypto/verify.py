from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
from crypto.keys import load_public_key


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