"""
Encryption Module - RSA and AES Implementation
Handles all encryption/decryption operations
"""

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import os


class EncryptionHandler:
    def __init__(self):
        self.aes_key = None
        self.rsa_key = None
        self.public_key = None
        
    # RSA Key Generation
    def generate_rsa_keys(self, key_size=2048):
        """Generate RSA public/private key pair"""
        try:
            key = RSA.generate(key_size)
            self.rsa_key = key
            self.public_key = key.publickey()
            
            print(f"[✓] RSA keys generated successfully ({key_size} bits)")
            return key.export_key(), key.publickey().export_key()
        except Exception as e:
            print(f"[✗] Error generating RSA keys: {e}")
            return None, None
    
    def load_rsa_key(self, key_data, is_private=True):
        """Load RSA key from data"""
        try:
            if is_private:
                self.rsa_key = RSA.import_key(key_data)
            else:
                self.public_key = RSA.import_key(key_data)
            return True
        except Exception as e:
            print(f"[✗] Error loading RSA key: {e}")
            return False
    
    # AES Encryption/Decryption
    def generate_aes_key(self, key_size=32):
        """Generate AES symmetric key (256-bit by default)"""
        self.aes_key = get_random_bytes(key_size)
        return self.aes_key
    
    def encrypt_aes(self, plaintext, key=None):
        """Encrypt data using AES-256 in CBC mode"""
        try:
            if key is None:
                key = self.aes_key
            
            if key is None:
                raise ValueError("AES key not set")
            
            # Convert plaintext to bytes if string
            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')
            
            # Generate random IV
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            # Pad and encrypt
            padded_data = pad(plaintext, AES.block_size)
            ciphertext = cipher.encrypt(padded_data)
            
            # Return IV + ciphertext (IV needed for decryption)
            return base64.b64encode(iv + ciphertext).decode('utf-8')
        except Exception as e:
            print(f"[✗] AES encryption error: {e}")
            return None
    
    def decrypt_aes(self, ciphertext, key=None):
        """Decrypt AES encrypted data"""
        try:
            if key is None:
                key = self.aes_key
            
            if key is None:
                raise ValueError("AES key not set")
            
            # Decode from base64
            encrypted_data = base64.b64decode(ciphertext)
            
            # Extract IV and ciphertext
            iv = encrypted_data[:16]
            actual_ciphertext = encrypted_data[16:]
            
            # Decrypt
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted_padded = cipher.decrypt(actual_ciphertext)
            
            # Unpad and return
            plaintext = unpad(decrypted_padded, AES.block_size)
            return plaintext.decode('utf-8')
        except Exception as e:
            print(f"[✗] AES decryption error: {e}")
            return None
    
    # RSA Encryption/Decryption (for key exchange)
    def encrypt_rsa(self, plaintext, public_key=None):
        """Encrypt data using RSA public key (typically for AES key)"""
        try:
            if public_key is None:
                public_key = self.public_key
            
            if public_key is None:
                raise ValueError("Public key not set")
            
            # Convert to bytes if string
            if isinstance(plaintext, str):
                plaintext = plaintext.encode('utf-8')
            
            cipher = PKCS1_OAEP.new(public_key)
            ciphertext = cipher.encrypt(plaintext)
            
            return base64.b64encode(ciphertext).decode('utf-8')
        except Exception as e:
            print(f"[✗] RSA encryption error: {e}")
            return None
    
    def decrypt_rsa(self, ciphertext):
        """Decrypt RSA encrypted data using private key"""
        try:
            if self.rsa_key is None:
                raise ValueError("Private key not set")
            
            # Decode from base64
            encrypted_data = base64.b64decode(ciphertext)
            
            cipher = PKCS1_OAEP.new(self.rsa_key)
            plaintext = cipher.decrypt(encrypted_data)
            
            return plaintext
        except Exception as e:
            print(f"[✗] RSA decryption error: {e}")
            return None
    
    # Secure Key Exchange
    def encrypt_key_for_transmission(self, aes_key, recipient_public_key):
        """Encrypt AES key using recipient's RSA public key"""
        try:
            recipient_key = RSA.import_key(recipient_public_key)
            cipher = PKCS1_OAEP.new(recipient_key)
            encrypted_key = cipher.encrypt(aes_key)
            return base64.b64encode(encrypted_key).decode('utf-8')
        except Exception as e:
            print(f"[✗] Key encryption error: {e}")
            return None
    
    def decrypt_received_key(self, encrypted_key):
        """Decrypt received AES key using own RSA private key"""
        try:
            encrypted_data = base64.b64decode(encrypted_key)
            cipher = PKCS1_OAEP.new(self.rsa_key)
            aes_key = cipher.decrypt(encrypted_data)
            self.aes_key = aes_key
            return aes_key
        except Exception as e:
            print(f"[✗] Key decryption error: {e}")
            return None


# Testing function
if __name__ == "__main__":
    print("=== Testing Encryption Module ===\n")
    
    handler = EncryptionHandler()
    
    # Test RSA
    print("1. Testing RSA Key Generation...")
    private_key, public_key = handler.generate_rsa_keys()
    
    # Test AES
    print("\n2. Testing AES Encryption...")
    aes_key = handler.generate_aes_key()
    print(f"[✓] AES Key generated: {len(aes_key)} bytes")
    
    test_message = "This is a secret message that needs encryption!"
    print(f"Original message: {test_message}")
    
    encrypted = handler.encrypt_aes(test_message)
    print(f"Encrypted: {encrypted[:50]}...")
    
    decrypted = handler.decrypt_aes(encrypted)
    print(f"Decrypted: {decrypted}")
    
    # Test RSA key exchange
    print("\n3. Testing RSA Key Exchange...")
    encrypted_key = handler.encrypt_key_for_transmission(aes_key, public_key)
    print(f"[✓] AES key encrypted for transmission")
    
    received_key = handler.decrypt_received_key(encrypted_key)
    print(f"[✓] AES key decrypted successfully")
    print(f"Keys match: {received_key == aes_key}")