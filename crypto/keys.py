from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os

KEYS_DIR = os.path.join(os.path.dirname(__file__), '..', 'keys')
os.makedirs(KEYS_DIR, exist_ok=True)


def generate_rsa_keys():
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

    print("✅ RSA keys generated → keys/rsa_private.pem & rsa_public.pem")
    return private_key, public_key


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