import os

def read_txt(file_path: str) -> str:

    if not os.path.exists(file_path):
        raise FileNotFoundError("File does not exist")

    if not file_path.lower().endswith(".txt"):
        raise ValueError("Not a TXT file")

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    content = content.strip()

    return content