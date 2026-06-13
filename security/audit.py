import os
import json
import base64
import hashlib
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from crypto.keys import (
    load_private_key,
    load_public_key
)

LOG_DIR = os.path.join(
    os.path.dirname(__file__),
    '..',
    'logs'
)

os.makedirs(LOG_DIR, exist_ok=True)

LOG_FILE = os.path.join(
    LOG_DIR,
    'audit.jsonl'
)


def compute_hash(data):
    """Compute SHA-256 hash of data with proper serialization."""
    try:
        return hashlib.sha256(
            json.dumps(
                data,
                sort_keys=True
            ).encode()
        ).hexdigest()
    except (TypeError, ValueError) as e:
        raise ValueError(f"Failed to compute hash: {e}")


def get_last_hash():
    """Get the last hash from audit log, or 'GENESIS' if no log exists."""
    if not os.path.exists(LOG_FILE):
        return "GENESIS"

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()

        if not lines:
            return "GENESIS"

        last_line = lines[-1].strip()
        if not last_line:
            return "GENESIS"

        try:
            last_entry = json.loads(last_line)
            return last_entry.get("current_hash", "GENESIS")
        except json.JSONDecodeError as e:
            print(f"⚠️  Warning: Corrupted audit log entry: {e}")
            return "GENESIS"

    except (IOError, OSError) as e:
        print(f"⚠️  Warning: Failed to read audit log: {e}")
        return "GENESIS"


def sign_log(entry):
    """Sign an audit log entry with RSA-PSS signature."""
    try:
        private_key = load_private_key()
    except FileNotFoundError as e:
        raise RuntimeError(f"Private key not found: {e}")
    except Exception as e:
        raise RuntimeError(f"Failed to load private key: {e}")

    try:
        data = json.dumps(
            entry,
            sort_keys=True
        ).encode()

        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(
                    hashes.SHA256()
                ),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        return base64.b64encode(
            signature
        ).decode()
    except Exception as e:
        raise RuntimeError(f"Failed to sign log entry: {e}")


def log_action(
        action,
        document,
        result):
    """Log an action to the audit trail with error handling."""
    try:
        previous_hash = get_last_hash()

        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "action": action,
            "document": document,
            "result": result,
            "previous_hash": previous_hash
        }

        entry["current_hash"] = compute_hash(entry)

        try:
            entry["signature"] = sign_log(entry)
        except RuntimeError as e:
            print(f"⚠️  Warning: Could not sign audit entry: {e}")
            entry["signature"] = None

        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry))
                f.write("\n")
        except (IOError, OSError) as e:
            print(f"❌ Error writing to audit log: {e}")
            raise

        print(
            f"[AUDIT] {action} -> {result}"
        )

    except Exception as e:
        print(f"❌ Error logging action: {e}")
        raise


def verify_log(entry):
    """Verify a single log entry signature with error handling."""
    try:
        public_key = load_public_key()
    except FileNotFoundError as e:
        print(f"❌ Public key not found: {e}")
        return False
    except Exception as e:
        print(f"❌ Failed to load public key: {e}")
        return False

    try:
        signature = base64.b64decode(
            entry["signature"]
        )

        temp = dict(entry)

        del temp["signature"]

        data = json.dumps(
            temp,
            sort_keys=True
        ).encode()

        try:

            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(
                        hashes.SHA256()
                    ),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )

            return True

        except InvalidSignature:

            return False

    except (ValueError, TypeError, KeyError) as e:
        print(f"❌ Error verifying log: {e}")
        return False


def verify_audit_file():
    """Verify audit file integrity with error handling."""
    if not os.path.exists(LOG_FILE):
        return False

    previous_hash = "GENESIS"

    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:

            for idx, line in enumerate(f, 1):

                try:
                    entry = json.loads(line.strip())
                except json.JSONDecodeError as e:
                    print(f"❌ Invalid JSON at line {idx}: {e}")
                    return False

                if entry.get("previous_hash") != previous_hash:
                    print(f"❌ Hash chain broken at line {idx}")
                    return False

                if entry.get("signature") and not verify_log(entry):
                    print(f"❌ Invalid signature at line {idx}")
                    return False

                previous_hash = entry.get("current_hash", "GENESIS")

        return True

    except (IOError, OSError) as e:
        print(f"❌ Error reading audit file: {e}")
        return False