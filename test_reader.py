print("PROGRAM STARTED")

from formats.txt_handler import read_txt

path = input("Enter TXT file path: ")

try:
    content = read_txt(path)

    print("\n===== CONTENT =====")
    print(content)

except Exception as e:
    print(f"Error: {e}")