from formats.pdf_handler import read_pdf

path = input("Enter PDF file path: ")

try:
    content = read_pdf(path)

    print("\n===== PDF CONTENT =====")
    print(content)

except Exception as e:
    print(f"Error: {e}")