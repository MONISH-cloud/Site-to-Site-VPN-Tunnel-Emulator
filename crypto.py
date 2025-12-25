# crypto_utils.py
from cryptography.fernet import Fernet

# The key is your "pre-shared key" or "secret" for the tunnel.
# In a real system, this would be exchanged securely.
def generate_key():
    """Generates a new Fernet key."""
    return Fernet.generate_key()

def get_fernet(key):
    """Returns a Fernet object for encryption/decryption."""
    return Fernet(key)

## crypto.py (or crypto_utils.py)

# ... rest of the code ...

# 🔑 Paste your generated key here!
ENCRYPTION_KEY = b'8xXIlnEIMd2Y191Q9-R6Wp6nwnA6G0dJ0_gyXrAiyeM='
