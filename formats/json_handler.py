import os
import json

def read_json(file_path):
    """Read and parse a JSON file with error handling."""
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError("File does not exist")

        if not file_path.endswith(".json"):
            raise ValueError("Not a JSON file")

        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data
    
    except FileNotFoundError as e:
        print(f"❌ File error: {e}")
        raise
    except json.JSONDecodeError as e:
        print(f"❌ Invalid JSON format: {e}")
        raise ValueError(f"Invalid JSON format: {e}")
    except (IOError, OSError) as e:
        print(f"❌ Error reading file: {e}")
        raise


def json_to_string(data):
    """
    Convert JSON object to a normalized string
    (important for hashing & signature)
    """
    try:
        return json.dumps(data, sort_keys=True, separators=(",", ":"))
    except (TypeError, ValueError) as e:
        raise ValueError(f"Failed to serialize JSON: {e}")