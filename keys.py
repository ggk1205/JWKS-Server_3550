from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta
import base64

# Store keys in memory
keys = {}

def generate_key_pair(kid, days_valid=30):
    """Generates a new RSA key pair and stores it with key id (kid) and expiry."""
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,  # Standard exponent for RSA
        key_size=2048  # 2048 bits provides good security
    )
    public_key = private_key.public_key()
    
    # Convert private key to PEM format for JWT encoding
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Calculate expiry timestamp
    expiry = datetime.utcnow() + timedelta(days=days_valid)
    
    # Store complete key information
    keys[kid] = {
        "private_key": private_pem,
        "public_key": public_key,
        "expiry": expiry,
        "kid": kid
    }

def get_jwk_from_public_key(kid, public_key, include_exp=False, expiry=None):
    """Helper function to convert a public key to JWK format."""
    public_numbers = public_key.public_numbers()
    jwk = {
        "kid": kid,
        "kty": "RSA",
        "alg": "RS256",
        "use": "sig",
        "n": int_to_base64(public_numbers.n),
        "e": int_to_base64(public_numbers.e),
    }
    
    # Include expiration if requested
    if include_exp and expiry:
        jwk["exp"] = int(expiry.timestamp())
    
    return jwk

def get_active_keys():
    """Returns active keys (i.e., non-expired) in JWKS format."""
    now = datetime.utcnow()
    active_keys = []
    
    for kid, key_info in keys.items():
        if key_info["expiry"] > now:
            jwk = get_jwk_from_public_key(kid, key_info["public_key"])
            active_keys.append(jwk)
            
    return active_keys

def get_all_keys():
    """Returns all keys (including expired) in JWKS format."""
    all_keys = []
    
    for kid, key_info in keys.items():
        jwk = get_jwk_from_public_key(
            kid, 
            key_info["public_key"], 
            include_exp=True,
            expiry=key_info["expiry"]
        )
        all_keys.append(jwk)
        
    return all_keys

def int_to_base64(n):
    """Convert an integer to a base64url-encoded string without padding."""
    # Convert integer to bytes with minimum length
    bytes_data = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    
    # Encode to base64url and remove padding
    encoded = base64.urlsafe_b64encode(bytes_data).decode('utf-8')
    return encoded.rstrip('=')

def get_key_by_kid(kid):
    """Return the key information associated with a given kid."""
    return keys.get(kid)

# Generate initial keys
generate_key_pair("key1", days_valid=30)  # Valid key
generate_key_pair("expired_key", days_valid=-1)  # Expired key