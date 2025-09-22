from flask import Flask, jsonify, request
import jwt
from keys import get_active_keys, get_key_by_kid, get_all_keys
from datetime import datetime, timedelta

app = Flask(__name__)

# JWT configuration
JWT_ISSUER = "jwks-server"
JWT_AUDIENCE = "test-audience"
JWT_EXPIRATION = timedelta(minutes=30)

@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    """Serve JWKS with active keys only (non-expired)."""
    return jsonify({"keys": get_active_keys()}), 200

@app.route("/auth", methods=["POST"])
def auth():
    """
    Issue a JWT signed with an active or expired key.
    
    Query parameters:
    - expired: If "true", returns a token signed with an expired key
    """
    # Check if expired token is requested
    expired = request.args.get("expired") == "true"
    
    # Select appropriate key ID
    kid = "expired_key" if expired else "key1"
    
    # Get the key information
    key_info = get_key_by_kid(kid)
    if not key_info:
        return jsonify({"error": f"Key with kid '{kid}' not found"}), 404

    # Determine expiration time
    if expired:
        # Create token that's already expired
        exp_time = datetime.utcnow() - timedelta(days=1)
    else:
        # Create valid token with future expiration
        exp_time = datetime.utcnow() + JWT_EXPIRATION

    # Define JWT headers with KID
    headers = {
        "kid": kid,
        "alg": "RS256"
    }
    
    # Define JWT payload
    payload = {
        "sub": "test_user",
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "exp": int(exp_time.timestamp()),
        "iat": int(datetime.utcnow().timestamp()),
    }
    
    # Create the signed JWT
    token = jwt.encode(
        payload=payload,
        key=key_info["private_key"], 
        algorithm="RS256",
        headers=headers
    )

    return jsonify({"token": token}), 200

if __name__ == "__main__":
    app.run(port=8080, debug=False)