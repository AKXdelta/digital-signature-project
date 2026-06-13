"""
Format dispatcher for signing documents.
Routes to the appropriate handler based on file type.
"""
import os
from formats.json_handler import read_json, json_to_string
from formats.pdf_handler import read_pdf
from formats.txt_handler import read_txt
from crypto.sign import sign_content, save_signature


def sign_file(filepath, key_path, algo="rsa"):
    """
    Sign a file and return the signature file path.
    Supports: PDF, JSON, TXT
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")
    
    ext = os.path.splitext(filepath)[1].lower()
    
    # Read content based on file type
    if ext == ".pdf":
        content = read_pdf(filepath)
    elif ext == ".json":
        data = read_json(filepath)
        content = json_to_string(data)
    elif ext == ".txt":
        content = read_txt(filepath)
    else:
        raise ValueError(f"Unsupported file format: {ext}")
    
    # Sign the content
    signature = sign_content(content)
    
    # Save signature
    sig_path = save_signature(signature, filepath)
    
    return sig_path
