"""
Cryptographic Engine for Secure File Encryption System
Core cryptographic functions using PyCryptodome
"""

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import secrets

# Cryptographic parameters
PBKDF2_ITERATIONS = 200000
SALT_SIZE = 16
IV_SIZE = 16
KEY_SIZE = 32  # 256 bits

def generate_random_bytes(size):
    """Generate cryptographically secure random bytes"""
    return get_random_bytes(size)

def derive_key(password, salt=None):
    """
    Derive a 256-bit AES key from password using PBKDF2
    
    Args:
        password (bytes): User password
        salt (bytes, optional): Salt for key derivation
    
    Returns:
        tuple: (key, salt)
    """
    if salt is None:
        salt = generate_random_bytes(SALT_SIZE)
    
    key = PBKDF2(password, salt, dkLen=KEY_SIZE, count=PBKDF2_ITERATIONS)
    return key, salt

def encrypt_data(plaintext, key):
    """
    Encrypt data using AES-256-CBC mode
    
    Args:
        plaintext (bytes): Data to encrypt
        key (bytes): 32-byte AES key
    
    Returns:
        tuple: (ciphertext, iv)
    """
    iv = generate_random_bytes(IV_SIZE)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # Pad the plaintext to AES block size
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    
    return ciphertext, iv

def decrypt_data(ciphertext, key, iv):
    """
    Decrypt data using AES-256-CBC mode
    
    Args:
        ciphertext (bytes): Encrypted data
        key (bytes): 32-byte AES key
        iv (bytes): Initialization vector
    
    Returns:
        bytes: Decrypted plaintext
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext)
    
    # Remove padding
    plaintext = unpad(decrypted_padded, AES.block_size)
    return plaintext

def compute_hash(data):
    """
    Compute SHA-256 hash of data
    
    Args:
        data (bytes): Input data
    
    Returns:
        bytes: 32-byte hash digest
    """
    hash_obj = SHA256.new(data=data)
    return hash_obj.digest()

def verify_integrity(original_hash, decrypted_data):
    """
    Verify data integrity using SHA-256 hash comparison
    
    Args:
        original_hash (bytes): Original hash value
        decrypted_data (bytes): Data to verify
    
    Returns:
        bool: True if hashes match
    """
    new_hash = compute_hash(decrypted_data)
    return secrets.compare_digest(original_hash, new_hash)