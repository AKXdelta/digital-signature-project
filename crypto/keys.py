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
    if path is None:
        path = os.path.join(KEYS_DIR, 'rsa_private.pem')
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def load_public_key(path=None):
    if path is None:
        path = os.path.join(KEYS_DIR, 'rsa_public.pem')
    with open(path, 'rb') as f:
        return serialization.load_pem_public_key(f.read())