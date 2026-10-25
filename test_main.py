"""Tests for the SQLite-backed JWKS server."""
import base64
import time

import jwt
import pytest

import main


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Flask test client that uses a fresh temporary database."""
    monkeypatch.setattr(main, "DB_FILE", str(tmp_path / "test.db"))
    main.init_db()
    main.seed_keys()
    main.app.config["TESTING"] = True
    with main.app.test_client() as test_client:
        yield test_client


def test_db_has_valid_and_expired_keys(client):
    """Seeding stores one valid and one expired key."""
    assert main.get_key(expired=False) is not None
    assert main.get_key(expired=True) is not None


def test_jwks_only_returns_valid_keys(client):
    """JWKS contains only the unexpired key."""
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    keys = resp.get_json()["keys"]
    assert len(keys) == 1
    assert keys[0]["kty"] == "RSA"
    assert keys[0]["alg"] == "RS256"
    assert keys[0]["kid"] == str(main.get_key(expired=False)[0])


def test_auth_json_returns_verifiable_jwt(client):
    """A JWT from /auth verifies against the key in the JWKS."""
    resp = client.post(
        "/auth", json={"username": "userABC", "password": "password123"}
    )
    assert resp.status_code == 200
    token = resp.get_data(as_text=True)
    kid = jwt.get_unverified_header(token)["kid"]
    jwks = client.get("/.well-known/jwks.json").get_json()
    jwk = next(k for k in jwks["keys"] if k["kid"] == kid)
    public_key = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)
    claims = jwt.decode(token, public_key, algorithms=["RS256"])
    assert claims["sub"] == "userABC"


def test_auth_basic_auth_uses_username(client):
    """HTTP Basic auth username ends up in the token."""
    creds = base64.b64encode(b"basicUser:password123").decode()
    resp = client.post("/auth", headers={"Authorization": "Basic " + creds})
    token = resp.get_data(as_text=True)
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["sub"] == "basicUser"


def test_auth_expired_returns_expired_jwt(client):
    """?expired gives a token signed by the expired key."""
    resp = client.post("/auth?expired=true")
    assert resp.status_code == 200
    token = resp.get_data(as_text=True)
    kid, pem, _ = main.get_key(expired=True)
    assert jwt.get_unverified_header(token)["kid"] == str(kid)
    public_key = main.load_private_key(pem).public_key()
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, public_key, algorithms=["RS256"])
    claims = jwt.decode(token, options={"verify_signature": False})
    assert claims["exp"] <= time.time()


def test_auth_without_keys_returns_500(tmp_path, monkeypatch):
    """With an empty database, /auth reports an error."""
    monkeypatch.setattr(main, "DB_FILE", str(tmp_path / "empty.db"))
    main.init_db()
    with main.app.test_client() as test_client:
        assert test_client.post("/auth").status_code == 500


def test_wrong_method_not_allowed(client):
    """Unsupported HTTP methods return 405."""
    assert client.get("/auth").status_code == 405
    assert client.post("/.well-known/jwks.json").status_code == 405


def test_int_to_base64url():
    """The standard RSA exponent 65537 encodes to AQAB."""
    assert main.int_to_base64url(65537) == "AQAB"
