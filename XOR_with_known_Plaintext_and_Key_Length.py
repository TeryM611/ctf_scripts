# Assuming you have some known plaintext and the length of the key
# It was encrypted using XOR 

# Given encrypted message in hex
hex_message = "585047514a594644066c544202404068065b00685a004a4a"

# Convert hex to bytes
cipher_bytes = bytes.fromhex(hex_message)

# ASCII values for "ictf"
known_plaintext = "ictf"
known_bytes = [ord(char) for char in known_plaintext]

# Determine the key by XORing first four bytes of ciphertext with known plaintext
key = bytes([cipher_bytes[i] ^ known_bytes[i] for i in range(4)])

# Decrypt the entire message
decrypted_bytes = bytes([cipher_bytes[i] ^ key[i % 4] for i in range(len(cipher_bytes))])

# Convert decrypted bytes to string
decrypted_message = decrypted_bytes.decode()

decrypted_message, key
