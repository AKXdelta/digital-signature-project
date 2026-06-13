from formats.txt_handler import read_txt
from crypto.sign import sign_content
from crypto.verify import verify_content

print("=== DIGITAL SIGNATURE TEST ===")

path = input("Enter TXT file path: ")

content = read_txt(path)

print("\nFile content:")
print(content)

signature = sign_content(content)

print("\nSignature generated!")

result = verify_content(content, signature)

print("\nVerification result:", result)