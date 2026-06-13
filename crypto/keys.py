from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
import os

KEYS_DIR = os.path.join(os.path.dirname(__file__), '..', 'keys')
os.makedirs(KEYS_DIR, exist_ok=True)


def generate_rsa_keys():
    """Generate RSA 2048-bit key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    with open(os.path.join(KEYS_DIR, 'rsa_private.pem'), 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(os.path.join(KEYS_DIR, 'rsa_public.pem'), 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("✅ RSA 2048-bit keys generated → keys/rsa_private.pem & rsa_public.pem")
    return private_key, public_key


def generate_ecdsa_keys():
    """Generate ECDSA P-256 key pair."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    with open(os.path.join(KEYS_DIR, 'ecdsa_private.pem'), 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(os.path.join(KEYS_DIR, 'ecdsa_public.pem'), 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    print("✅ ECDSA P-256 keys generated → keys/ecdsa_private.pem & ecdsa_public.pem")
    return private_key, public_key


def generate_keys(algo="rsa", prefix="keys/ma_cle"):
    """Generate cryptographic keys based on algorithm."""
    try:
        if algo.lower() == "rsa":
            return generate_rsa_keys()
        elif algo.lower() == "ecdsa":
            return generate_ecdsa_keys()
        else:
            raise ValueError(f"Unsupported algorithm: {algo}. Use 'rsa' or 'ecdsa'")
    except Exception as e:
        raise RuntimeError(f"Key generation failed: {e}")


def load_private_key(path=None):
    """Load a private key from file with error handling."""
    try:
        if path is None:
            path = os.path.join(KEYS_DIR, 'rsa_private.pem')
        
        if not os.path.exists(path):
            raise FileNotFoundError(f"Private key file not found: {path}")
        
        with open(path, 'rb') as f:
            key_data = f.read()
            if not key_data:
                raise ValueError(f"Private key file is empty: {path}")
        
        return serialization.load_pem_private_key(key_data, password=None)
    except (IOError, OSError) as e:
        raise RuntimeError(f"Failed to read private key file: {e}")


def load_public_key(path=None):
    """Load a public key from file with error handling."""
    try:
        if path is None:
            path = os.path.join(KEYS_DIR, 'rsa_public.pem')
        
        if not os.path.exists(path):
            raise FileNotFoundError(f"Public key file not found: {path}")
        
        with open(path, 'rb') as f:
            key_data = f.read()
            if not key_data:
                raise ValueError(f"Public key file is empty: {path}")
        
        return serialization.load_pem_public_key(key_data)
    except (IOError, OSError) as e:
        raise RuntimeError(f"Failed to read public key file: {e}")