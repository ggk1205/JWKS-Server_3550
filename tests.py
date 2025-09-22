# tests.py
import pytest
from app import app

@pytest.fixture
def client():
    app.config["TESTING"] = True
    client = app.test_client()
    yield client

def test_jwks_endpoint(client):
    """Test the JWKS endpoint for active keys."""
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    assert "keys" in response.json

def test_auth_endpoint(client):
    """Test the /auth endpoint for a valid JWT."""
    response = client.post("/auth")
    assert response.status_code == 200
    assert "token" in response.json

def test_expired_auth_endpoint(client):
    """Test the /auth endpoint for an expired JWT."""
    response = client.post("/auth?expired=true")
    assert response.status_code == 200
    assert "token" in response.json

def test_invalid_kid(client):
    """Test for an invalid kid."""
    response = client.post("/auth?kid=invalid_key")
    assert response.status_code == 404
    assert response.json["error"] == "Key with kid 'invalid_key' not found"

def test_valid_kid(client):
    """Test for a valid kid (key1)."""
    response = client.post("/auth?kid=key1")
    assert response.status_code == 200
    assert "token" in response.json
