from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from keys import load_private_key
from hash import hash_file
import os

SIGNATURES_DIR = os.path.join(os.path.dirname(__file__), '..', 'signatures')
os.makedirs(SIGNATURES_DIR, exist_ok=True)


def sign_file(filepath: str) -> str:
    """
    Sign a file using RSA-PSS
    1. Hash the file with SHA-256
    2. Encrypt the hash with RSA private key
    3. Save signature to .sig file
    """
    # Étape 1 : lire le fichier
    with open(filepath, 'rb') as f:
        content = f.read()

    # Étape 2 : charger la clé privée
    private_key = load_private_key()

    # Étape 3 : signer (hash + chiffrement RSA-PSS)
    signature = private_key.sign(
        content,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    # Étape 4 : sauvegarder la signature
    filename = os.path.basename(filepath)
    sig_path = os.path.join(SIGNATURES_DIR, filename + '.sig')
    with open(sig_path, 'wb') as f:
        f.write(signature)

    print(f"✅ Signature saved → {sig_path}")
    return sig_path