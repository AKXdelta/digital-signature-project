from PyPDF2 import PdfReader
import os

def read_pdf(file_path: str) -> str:
    """Read and extract text from PDF file with error handling."""
    try:
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        if not file_path.lower().endswith(".pdf"):
            raise ValueError("Not a PDF file")

        reader = PdfReader(file_path)

        text = ""

        for idx, page in enumerate(reader.pages):
            try:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
            except Exception as e:
                print(f"⚠️  Warning: Failed to extract text from page {idx + 1}: {e}")

        return text.strip()
    
    except FileNotFoundError as e:
        print(f"❌ {e}")
        raise
    except ValueError as e:
        print(f"❌ {e}")
        raise
    except Exception as e:
        print(f"❌ Error reading PDF: {e}")
        raise