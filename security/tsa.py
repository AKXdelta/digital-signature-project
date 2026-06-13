
import os
import hashlib
import requests

from rfc3161ng import RemoteTimestamper
from security.audit import log_action

# Serveur TSA RFC3161
TSA_URL = "http://timestamp.digicert.com"

# Dossier de stockage des timestamps
TIMESTAMP_DIR = os.path.join(
    os.path.dirname(__file__),
    "..",
    "timestamps"
)

os.makedirs(TIMESTAMP_DIR, exist_ok=True)


def check_tsa_server():
    """
    Vérifie que le serveur TSA est joignable.
    """
    try:
        requests.get(
            TSA_URL,
            timeout=5
        )
        return True

    except Exception:
        return False


def create_timestamp(document_path):
    """
    Génère un timestamp RFC3161 pour un document.
    """

    if not os.path.exists(document_path):

        log_action(
            "TIMESTAMP",
            document_path,
            "FILE_NOT_FOUND"
        )

        return None

    try:

        with open(document_path, "rb") as f:
            data = f.read()

        # Hachage SHA-256 du document
        digest = hashlib.sha256(data).digest()

        # Création de la requête TSA
        tsa = RemoteTimestamper(TSA_URL)

        # Génération du token RFC3161
        token = tsa(data=digest)

        # Sauvegarde du timestamp
        ts_file = os.path.join(
            TIMESTAMP_DIR,
            os.path.basename(document_path) + ".tsr"
        )

        with open(ts_file, "wb") as f:
            f.write(token)

        log_action(
            "TIMESTAMP",
            document_path,
            "SUCCESS"
        )

        return ts_file

    except Exception as e:

        log_action(
            "TIMESTAMP",
            document_path,
            "FAILED"
        )

        print(f"Erreur TSA : {e}")

        return None


def verify_timestamp(document_path, ts_file):
    """
    Vérifie qu'un timestamp correspond au document.
    """

    if not os.path.exists(document_path):

        result = {
            "status": "INVALID",
            "reason": "Document not found"
        }

        log_action(
            "VERIFY_TIMESTAMP",
            document_path,
            result["status"]
        )

        return result

    if not os.path.exists(ts_file):

        result = {
            "status": "INVALID",
            "reason": "Timestamp file not found"
        }

        log_action(
            "VERIFY_TIMESTAMP",
            document_path,
            result["status"]
        )

        return result

    try:

        with open(document_path, "rb") as f:
            data = f.read()

        digest = hashlib.sha256(data).digest()

        with open(ts_file, "rb") as f:
            token = f.read()

        tsa = RemoteTimestamper(TSA_URL)

        tsa.check(
            token,
            data=digest
        )

        result = {
            "status": "VALID",
            "document": document_path,
            "timestamp_file": ts_file
        }

    except Exception as e:

        result = {
            "status": "INVALID",
            "document": document_path,
            "timestamp_file": ts_file,
            "reason": str(e)
        }

    log_action(
        "VERIFY_TIMESTAMP",
        document_path,
        result["status"]
    )

    return result


def timestamp_report(document_path, ts_file):
    """
    Génère un rapport détaillé.
    """

    result = verify_timestamp(
        document_path,
        ts_file
    )

    report = {
        "document": document_path,
        "timestamp_file": ts_file,
        "timestamp_status": result["status"]
    }

    if "reason" in result:
        report["reason"] = result["reason"]

    return report


