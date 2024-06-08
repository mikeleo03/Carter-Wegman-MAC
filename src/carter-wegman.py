import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

# Generate random keys
hash_key = get_random_bytes(16).hex()  # Hex encoded hash key
aes_key = get_random_bytes(16)  # AES key

# Polynomial hash function
def polynomial_hash(message: str, key: str, prime: int) -> int:
    p = 31
    hash_value = 0
    p_power = 1

    for i, char in enumerate(message):
        hash_value = (hash_value + (ord(char) + ord(key[i % len(key)])) * p_power) % prime
        p_power = (p_power * p) % prime

    return hash_value

# AES encryption
def encrypt_with_aes(plaintext: str, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.update(str(plaintext).encode())
    ciphertext, tag = cipher.encrypt_and_digest(b"")
    return cipher.nonce + ciphertext + tag

# AES decryption
def decrypt_with_aes(ciphertext: bytes, key: bytes) -> str:
    iv = ciphertext[:16]
    encrypted_data = ciphertext[16:-16]
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.update(str(hash_value).encode())

# Generate MAC using GCM mode
def generate_mac(message: str, hash_key: str, aes_key: bytes) -> bytes:
    hash_value = polynomial_hash(message, hash_key, int(1e9 + 9))
    return encrypt_with_aes(hash_value, aes_key)

# Verify MAC using GCM mode
def verify_mac(message: str, received_mac: bytes, hash_key: str, aes_key: bytes) -> bool:
    hash_value = polynomial_hash(message, hash_key, int(1e9 + 9))
    tag = received_mac[-16:]
    decrypted_mac = decrypt_with_aes(received_mac, aes_key)
    try:
        decrypted_mac.verify(tag)
        return True
    except ValueError:
        return False

# Verify MAC using GCM mode
def verify_mac(message: str, received_mac: bytes, hash_key: str, aes_key: bytes) -> bool:
    hash_value = polynomial_hash(message, hash_key, int(1e9 + 9))
    nonce = received_mac[:16]
    ciphertext = received_mac[16:-16]
    tag = received_mac[-16:]
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    cipher.update(str(hash_value).encode())
    try:
        cipher.verify(tag)
        return True
    except ValueError:
        return False


# Test scenarios
def test_scenarios():
    message = 'buku:3'
    
    # 1. Normal Condition
    print("\n=== Normal Condition ===")
    mac = generate_mac(message, hash_key, aes_key)
    print('Generated MAC:', mac.hex())
    is_valid = verify_mac(message, mac, hash_key, aes_key)
    print('Is MAC valid?', is_valid)

    # 2. Message Modified
    print("\n=== Message Modified ===")
    modified_message = 'buku:4'
    is_valid = verify_mac(modified_message, mac, hash_key, aes_key)
    print('Is MAC valid with modified message?', is_valid)

    # 3. MAC Modified
    print("\n=== MAC Modified ===")
    modified_mac = bytearray(mac)
    modified_mac[0] = (modified_mac[0] + 1) % 256  # Modify the first byte of the nonce
    is_valid = verify_mac(message, bytes(modified_mac), hash_key, aes_key)
    print('Is MAC valid with modified MAC?', is_valid)

    # 4. Wrong Hash Key
    print("\n=== Wrong Hash Key ===")
    wrong_hash_key = get_random_bytes(16).hex()
    is_valid = verify_mac(message, mac, wrong_hash_key, aes_key)
    print('Is MAC valid with wrong hash key?', is_valid)

    # 5. Wrong AES Key
    print("\n=== Wrong AES Key ===")
    wrong_aes_key = get_random_bytes(16)
    is_valid = verify_mac(message, mac, hash_key, wrong_aes_key)
    print('Is MAC valid with wrong AES key?', is_valid)

    # 6. Wrong IV Handling (simulated by modifying nonce)
    print("\n=== Wrong IV Handling ===")
    modified_nonce_mac = bytearray(mac)
    modified_nonce_mac[:16] = get_random_bytes(16)  # Modify the nonce
    is_valid = verify_mac(message, bytes(modified_nonce_mac), hash_key, aes_key)
    print('Is MAC valid with wrong IV handling?', is_valid)

# Example usage
if __name__ == "__main__":
    test_scenarios()
