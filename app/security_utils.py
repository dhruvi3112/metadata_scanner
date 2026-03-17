import os
from cryptography.fernet import Fernet

def get_encryption_key():
    """Get the ENCRYPTION_KEY from environment variables."""
    key = os.environ.get("ENCRYPTION_KEY")
    if not key:
        return None
    return key.encode()

def encrypt_data(plain_text):
    """Encrypt plain text using the ENCRYPTION_KEY."""
    if not plain_text:
        return ""
    
    key = get_encryption_key()
    if not key:
        return plain_text # Safety fallback
        
    f = Fernet(key)
    return f.encrypt(plain_text.encode()).decode()

def decrypt_data(cipher_text):
    """Decrypt cipher text using the ENCRYPTION_KEY."""
    if not cipher_text:
        return ""
        
    key = get_encryption_key()
    if not key:
        return cipher_text
        
    try:
        # Check if it looks like a Fernet token (starts with gAAAA)
        if not cipher_text.startswith("gAAAA"):
             return cipher_text
             
        f = Fernet(key)
        return f.decrypt(cipher_text.encode()).decode()
    except Exception as e:
        print(f"[Security] Decryption failed: {e}")
        return cipher_text # Fallback to plain text if decryption fails
