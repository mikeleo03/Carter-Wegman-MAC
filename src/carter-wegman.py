import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class HashFunction:
    """Class to handle polynomial hashing."""
    
    def __init__(self, key: str):
        self.key = key
    
    def polynomial_hash(self, message: str, prime: int = int(1e9 + 9)) -> int:
        p = 31
        hash_value = 0
        p_power = 1
        
        for i, char in enumerate(message):
            hash_value = (hash_value + (ord(char) + ord(self.key[i % len(self.key)])) * p_power) % prime
            p_power = (p_power * p) % prime
        
        return hash_value
    
class AESCipher:
    """Class to handle AES encryption and decryption."""
    
    def __init__(self, key: bytes):
        self.key = key
    
    def encrypt(self, plaintext: str) -> bytes:
        cipher = AES.new(self.key, AES.MODE_GCM)
        cipher.update(str(plaintext).encode())
        ciphertext, tag = cipher.encrypt_and_digest(b"")
        return cipher.nonce + ciphertext + tag
    
    def decrypt(self, ciphertext: bytes):
        iv = ciphertext[:16]
        encrypted_data = ciphertext[16:-16]
        tag = ciphertext[-16:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=iv)
        return cipher, encrypted_data, tag

class MACGenerator:
    """Class to generate and verify MAC using hashing and AES."""
    
    def __init__(self, hash_function: HashFunction, aes_cipher: AESCipher):
        self.hash_function = hash_function
        self.aes_cipher = aes_cipher
    
    def generate_mac(self, message: str) -> bytes:
        hash_value = self.hash_function.polynomial_hash(message)
        return self.aes_cipher.encrypt(hash_value)
    
    def verify_mac(self, message: str, received_mac: bytes) -> bool:
        hash_value = self.hash_function.polynomial_hash(message)
        cipher, encrypted_data, tag = self.aes_cipher.decrypt(received_mac)
        cipher.update(str(hash_value).encode())
        try:
            cipher.verify(tag)
            return True
        except ValueError:
            return False
    
# Test scenarios
def test_scenarios():
    hash_key = get_random_bytes(16).hex()
    aes_key = get_random_bytes(16)

    hash_function = HashFunction(hash_key)
    aes_cipher = AESCipher(aes_key)
    mac_generator = MACGenerator(hash_function, aes_cipher)
    
    message = 'buku:3'
    
    # 1. Normal Condition
    print("\n=== Normal Condition ===")
    mac = mac_generator.generate_mac(message)
    print('Generated MAC:', mac.hex())
    is_valid = mac_generator.verify_mac(message, mac)
    print('Is MAC valid?', is_valid)

    # 2. Message Modified
    print("\n=== Message Modified ===")
    modified_message = 'buku:4'
    is_valid = mac_generator.verify_mac(modified_message, mac)
    print('Is MAC valid with modified message?', is_valid)

    # 3. MAC Modified
    print("\n=== MAC Modified ===")
    modified_mac = bytearray(mac)
    modified_mac[0] = (modified_mac[0] + 1) % 256  # Modify the first byte of the nonce
    is_valid = mac_generator.verify_mac(message, bytes(modified_mac))
    print('Is MAC valid with modified MAC?', is_valid)

    # 4. Wrong Hash Key
    print("\n=== Wrong Hash Key ===")
    wrong_hash_key = get_random_bytes(16).hex()
    wrong_hash_function = HashFunction(wrong_hash_key)
    wrong_mac_generator = MACGenerator(wrong_hash_function, aes_cipher)
    is_valid = wrong_mac_generator.verify_mac(message, mac)
    print('Is MAC valid with wrong hash key?', is_valid)

    # 5. Wrong AES Key
    print("\n=== Wrong AES Key ===")
    wrong_aes_key = get_random_bytes(16)
    wrong_aes_cipher = AESCipher(wrong_aes_key)
    wrong_mac_generator = MACGenerator(hash_function, wrong_aes_cipher)
    is_valid = wrong_mac_generator.verify_mac(message, mac)
    print('Is MAC valid with wrong AES key?', is_valid)

    # 6. Wrong IV Handling (simulated by modifying nonce)
    print("\n=== Wrong IV Handling ===")
    modified_nonce_mac = bytearray(mac)
    modified_nonce_mac[:16] = get_random_bytes(16)  # Modify the nonce
    is_valid = mac_generator.verify_mac(message, bytes(modified_nonce_mac))
    print('Is MAC valid with wrong IV handling?', is_valid)

# Example usage
if __name__ == "__main__":
    test_scenarios()
