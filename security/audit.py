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
    return hashlib.sha256(
        json.dumps(
            data,
            sort_keys=True
        ).encode()
    ).hexdigest()


def get_last_hash():

    if not os.path.exists(LOG_FILE):
        return "GENESIS"

    with open(LOG_FILE, "r") as f:
        lines = f.readlines()

    if not lines:
        return "GENESIS"

    last_entry = json.loads(lines[-1])

    return last_entry["current_hash"]


def sign_log(entry):

    private_key = load_private_key()

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


def log_action(
        action,
        document,
        result):

    previous_hash = get_last_hash()

    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "action": action,
        "document": document,
        "result": result,
        "previous_hash": previous_hash
    }

    entry["current_hash"] = compute_hash(entry)

    entry["signature"] = sign_log(entry)

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry))
        f.write("\n")

    print(
        f"[AUDIT] {action} -> {result}"
    )


def verify_log(entry):

    public_key = load_public_key()

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


def verify_audit_file():

    if not os.path.exists(LOG_FILE):
        return False

    previous_hash = "GENESIS"

    with open(LOG_FILE, "r") as f:

        for line in f:

            entry = json.loads(line)

            if entry["previous_hash"] != previous_hash:
                return False

            if not verify_log(entry):
                return False

            previous_hash = entry["current_hash"]

    return True