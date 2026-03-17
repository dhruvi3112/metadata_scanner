import os
from cryptography.fernet import Fernet

def get_encryption_key():
    """Get the ENCRYPTION_KEY from environment variables."""
    key = os.environ.get("ENCRYPTION_KEY")
    if not key:
        # Fallback for security. Ideally, this should always be set in .env
        # But for development, we can warn or handle it.
        return None
    return key.encode()

def encrypt_data(plain_text):
    """Encrypt plain text using the ENCRYPTION_KEY."""
    if not plain_text:
        return ""
    
    key = get_encryption_key()
    if not key:
        return plain_text # Return as-is if no key found (not ideal)
        
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
        f = Fernet(key)
        # Check if it looks like a Fernet token (usually starts with gAAAA)
        # If it doesn't, it might be legacy plain text
        if not cipher_text.startswith("gAAAA"):
             return cipher_text
             
        return f.decrypt(cipher_text.encode()).decode()
    except Exception as e:
        print(f"[Security] Decryption failed: {e}")
        return cipher_text # Return as-is if decryption fails (might be plain text)
