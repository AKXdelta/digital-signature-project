import os

def read_txt(file_path: str) -> str:
    """Read a text file with error handling."""
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError("File does not exist")

        if not file_path.lower().endswith(".txt"):
            raise ValueError("Not a TXT file")

        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        return content.strip()
    
    except FileNotFoundError as e:
        print(f"❌ {e}")
        raise
    except ValueError as e:
        print(f"❌ {e}")
        raise
    except (IOError, OSError) as e:
        print(f"❌ Error reading file: {e}")
        raise