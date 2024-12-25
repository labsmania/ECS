def xor_encrypt_decrypt(input_string, key):
    input_bytes = bytearray(input_string, 'utf-8')
    output_bytes = bytearray([byte ^ key for byte in input_bytes])
    return output_bytes

key = 123 
original_text = input("Enter the message\n")

encrypted_bytes = xor_encrypt_decrypt(original_text, key)
encrypted_text = encrypted_bytes.hex()
print(f"Encrypted (hex): {encrypted_text}")

decrypted_bytes = xor_encrypt_decrypt(bytes.fromhex(encrypted_text).decode('utf-8'), key)
decrypted_text = decrypted_bytes.decode('utf-8', 'ignore')
print(f"Decrypted: {decrypted_text}")
