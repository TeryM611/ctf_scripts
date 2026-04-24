from pwn import *
from Cryptodome.Util.Padding import pad


conn = None

# Function to interact with the oracle
def encrypt_oracle(input_text):
    global conn  # Use the global connection variable
    try:
        conn.recvuntil(b'Enter text to be encrypted: ')  # Use bytes for recvuntil
        conn.sendline(input_text.encode())  # Encode input_text to bytes
        response = conn.recvline().strip().decode()  # Decode the received line
        
        # Print the raw response for debugging
        print(f"Raw response: {response}")
        
        # Extract the hexadecimal portion of the response
        if response.startswith('0x'):
            hex_data = response[2:]  # Remove '0x' prefix
            # Ensure the length is a multiple of 32 (16 bytes * 2 characters per byte)
            valid_length = (len(hex_data) // 32) * 32
            hex_data = hex_data[:valid_length]  # Truncate to valid length
            if not hex_data:
                raise ValueError("No valid hexadecimal data found")
            # Convert to bytes
            ct_bytes = bytes.fromhex(hex_data)
            return ct_bytes
        else:
            # Handle unexpected responses
            print(f"Unexpected response: {response}")
            raise ValueError("Invalid response format")
    except (ValueError, EOFError) as e:
        print(f"Error: {e}. Reconnecting...")
        conn.close()
        conn = remote('server_goes_here', 7150)  # Reconnect to the server
        return encrypt_oracle(input_text)  # Retry the request

# Connect to the server
conn = remote('server_goes_here', 7150)  # Replace with actual server details

# Determine the secret length. Send inputs of varying lengths and observe ciphertext length
block_size = 16
secret_length = None
for i in range(1, 100):
    input_text = 'A' * i
    ct = encrypt_oracle(input_text)
    if secret_length is None:
        secret_length = len(ct) - len(pad(input_text.encode(), block_size))
    else:
        if len(ct) - len(pad(input_text.encode(), block_size)) != secret_length:
            secret_length = len(ct) - len(pad(input_text.encode(), block_size))
            break
print(f"Secret length: {secret_length}")

# Align the secret. Send inputs to position the secret at a block boundary
input_text = 'A' * (block_size - (secret_length % block_size))
ct = encrypt_oracle(input_text)
print(f"Aligned ciphertext: {ct.hex()}")

# Recover the secret
secret = b''
for i in range(secret_length):
    # Craft input to shift the secret into a known position
    input_text = 'A' * (block_size - (secret_length % block_size) - 1 - i)
    ct = encrypt_oracle(input_text)
    
    # Brute-force the byte
    for byte in range(256):
        time.sleep(2)
        test_input = input_text.encode() + secret + bytes([byte])
        test_ct = encrypt_oracle(test_input.decode())
        if test_ct[:block_size] == ct[:block_size]:
            secret += bytes([byte])
            break
    print(f"Recovered secret: {secret.decode()}")

conn.close()
