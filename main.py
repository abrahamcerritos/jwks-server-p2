"""JWKS server backed by SQLite.

CSCE 3550 - Project 2: Extending the JWKS server.
Stores RSA private keys in a SQLite database and serves:
  POST /auth                   -> signed JWT (expired key if ?expired)
  GET  /.well-known/jwks.json  -> public keys for all unexpired keys
"""
import base64
import sqlite3
import time

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, jsonify, request

DB_FILE = "totally_not_my_privateKeys.db"

app = Flask(__name__)


# ---------- Database helpers ----------

def get_connection():
    """Open a connection to the SQLite database file."""
    return sqlite3.connect(DB_FILE)


def init_db():
    """Create the keys table if it does not exist yet."""
    conn = get_connection()
    conn.execute(
        "CREATE TABLE IF NOT EXISTS keys("
        "kid INTEGER PRIMARY KEY AUTOINCREMENT, "
        "key BLOB NOT NULL, "
        "exp INTEGER NOT NULL)"
    )
    conn.commit()
    conn.close()


def save_key(pem, exp):
    """Insert a PEM-encoded private key using a parameterized query."""
    conn = get_connection()
    conn.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (pem, exp))
    conn.commit()
    conn.close()


def get_key(expired=False):
    """Return (kid, pem, exp) for one expired or one valid key, or None."""
    now = int(time.time())
    if expired:
        query = "SELECT kid, key, exp FROM keys WHERE exp <= ? LIMIT 1"
    else:
        query = "SELECT kid, key, exp FROM keys WHERE exp > ? LIMIT 1"
    conn = get_connection()
    row = conn.execute(query, (now,)).fetchone()
    conn.close()
    return row


def get_valid_keys():
    """Return (kid, pem) for every key that has not expired."""
    now = int(time.time())
    conn = get_connection()
    rows = conn.execute(
        "SELECT kid, key FROM keys WHERE exp > ?", (now,)
    ).fetchall()
    conn.close()
    return rows


# ---------- Key helpers ----------

def generate_private_key_pem():
    """Generate a 2048-bit RSA key and serialize it as PKCS1 PEM."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def load_private_key(pem):
    """Deserialize a PEM private key read from the database."""
    return serialization.load_pem_private_key(pem, password=None)


def int_to_base64url(value):
    """Encode an integer as unpadded base64url (used for JWK n and e)."""
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def seed_keys():
    """Store one expired key and one key valid for an hour."""
    now = int(time.time())
    save_key(generate_private_key_pem(), now - 3600)
    save_key(generate_private_key_pem(), now + 3600)


# ---------- Endpoints ----------

@app.route("/auth", methods=["POST"])
def auth():
    """Sign a JWT with a key from the DB (expired key if ?expired)."""
    expired = "expired" in request.args
    row = get_key(expired)
    if row is None:
        return jsonify({"error": "no suitable key found"}), 500
    kid, pem, exp = row

    # Mock authentication: accept Basic auth or a JSON body.
    body = request.get_json(silent=True) or {}
    username = body.get("username", "userABC")
    if request.authorization and request.authorization.username:
        username = request.authorization.username

    payload = {"sub": username, "exp": exp}
    token = jwt.encode(
        payload,
        load_private_key(pem),
        algorithm="RS256",
        headers={"kid": str(kid)},
    )
    return token, 200


@app.route("/.well-known/jwks.json", methods=["GET"])
def jwks():
    """Return a JWKS with the public part of every unexpired key."""
    keys = []
    for kid, pem in get_valid_keys():
        numbers = load_private_key(pem).public_key().public_numbers()
        keys.append({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": str(kid),
            "n": int_to_base64url(numbers.n),
            "e": int_to_base64url(numbers.e),
        })
    return jsonify({"keys": keys}), 200


if __name__ == "__main__":
    init_db()
    seed_keys()
    app.run(host="127.0.0.1", port=8080)
