import os
import json

def read_json(file_path):
    # Check if file exists
    if not os.path.exists(file_path):
        raise FileNotFoundError("File does not exist")

    # Check extension
    if not file_path.endswith(".json"):
        raise ValueError("Not a JSON file")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError:
        raise ValueError("Invalid JSON format")
    except Exception as e:
        raise Exception(f"Error reading file: {e}")

    return data


def json_to_string(data):
    """
    Convert JSON object to a normalized string
    (important for hashing & signature)
    """
    return json.dumps(data, sort_keys=True, separators=(",", ":"))