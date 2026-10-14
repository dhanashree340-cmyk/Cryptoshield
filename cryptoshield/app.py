"""
app.py
CryptoShield Web Dashboard

A Flask web UI over the SAME crypto modules used before:
  key_manager.py      -> password + random salt -> PBKDF2 -> HKDF -> encryption/auth keys
  integrity_module.py -> SHA-256 hashing
  encrypt_module.py   -> ChaCha20-Poly1305 authenticated encryption
  auth_module.py      -> HMAC-SHA256 envelope authentication
  audit_module.py     -> audit log (logs/audit_log.txt)
  auth/               -> register / login / logout (Flask sessions)

Run with:  python app.py
Then open: http://127.0.0.1:5000 in your browser.
"""

import os
import hmac
import secrets
import datetime

from flask import Flask, render_template, request, jsonify, session

from key_manager import generate_salt, derive_keys_from_password
from integrity_module import sha256_hash, bundle_fingerprint
from encrypt_module import encrypt, decrypt
from auth_module import compute_hmac, verify_hmac, build_envelope
from audit_module import log, read_log
from auth import auth_bp
from auth.utils import (
    init_db, login_required, current_user, save_bundle, get_bundle, update_ciphertext,
    valid_password, is_blocked, record_failure, clear_failures,
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FILENAME_TAG = b"web-message"   # stand-in "filename" covered by the HMAC envelope
MAX_TEXT_BYTES = 100_000

GENERIC_FAIL = "Invalid password or corrupted encrypted data."


def load_secret_key() -> bytes:
    """Secret used to sign login cookies. Set SECRET_KEY, or one is created in instance/."""
    env = os.environ.get("SECRET_KEY")
    if env:
        return env.encode()
    path = os.path.join(BASE_DIR, "instance", "secret_key")
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    key = secrets.token_bytes(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return key


app = Flask(__name__)
app.config.update(
    SECRET_KEY=load_secret_key(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=datetime.timedelta(minutes=30),
    MAX_CONTENT_LENGTH=1024 * 1024,
)
init_db()
app.register_blueprint(auth_bp)


# ---------- CSRF protection + safe headers ----------

def csrf_token() -> str:
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


@app.context_processor
def inject_csrf():
    return {"csrf_token": csrf_token}


@app.before_request
def csrf_protect():
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(sent, expected):
            return jsonify({"error": "Invalid or missing security token. Reload the page."}), 400


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Cache-Control"] = "no-store"   # don't cache decrypted data
    return resp


# ---------- helpers ----------

def now_str() -> str:
    return datetime.datetime.now().strftime("%d %b %Y, %H:%M:%S")


def bundle_is_intact(bundle) -> bool:
    """Password-free check: does the stored bundle still match its fingerprint?"""
    current = bundle_fingerprint(bundle["salt"], bundle["nonce"], bundle["ciphertext"], bundle["hmac_tag"])
    return hmac.compare_digest(current, bundle["bundle_digest"])


def aad_for(user, salt: bytes) -> bytes:
    """Data bound to the encryption: the salt and the owner's username."""
    return salt + user["username"].encode()


# ---------- pages ----------

@app.route("/")
@login_required
def index():
    user = current_user()
    bundle = get_bundle(user["id"])
    # NOTE: no keys (or anything secret) are passed to the template.
    return render_template(
        "index.html",
        username=user["username"],
        last_check=now_str(),
        has_bundle=bundle is not None,
        bundle_created=bundle["created_at"] if bundle else None,
    )


# ---------- API ----------

@app.route("/api/encrypt", methods=["POST"])
@login_required
def api_encrypt():
    user = current_user()
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    password = data.get("password", "")
    confirm = data.get("confirm_password", "")

    if not isinstance(text, str) or not isinstance(password, str) or not isinstance(confirm, str):
        return jsonify({"error": "Invalid input"}), 400
    if not text:
        return jsonify({"error": "Empty input"}), 400
    if len(text.encode()) > MAX_TEXT_BYTES:
        return jsonify({"error": "Data is too large (limit 100 KB)."}), 400
    if not valid_password(password):
        return jsonify({"error": "Encryption password must be 8-128 characters."}), 400
    if password != confirm:
        return jsonify({"error": "Passwords do not match."}), 400

    plaintext = text.encode()
    plaintext_hash = sha256_hash(plaintext)

    # Fresh random salt for every encryption -> keys come from the password
    salt = generate_salt()
    enc_key, auth_key = derive_keys_from_password(password, salt)
    aad = aad_for(user, salt)

    result = encrypt(plaintext, enc_key, aad)
    nonce, ciphertext = result["nonce"], result["ciphertext"]

    envelope = build_envelope(nonce, ciphertext, aad + FILENAME_TAG)
    hmac_tag = compute_hmac(auth_key, envelope)
    digest = bundle_fingerprint(salt, nonce, ciphertext, hmac_tag)

    save_bundle(user["id"], salt, nonce, ciphertext, hmac_tag, plaintext_hash, digest)
    clear_failures(("decrypt", user["id"]))

    log("ENCRYPTION SUCCESS", user["username"])

    # Only non-secret values go back to the browser (no keys, no password)
    return jsonify({
        "sha256_hash": plaintext_hash,
        "salt_id": salt.hex()[:8],
        "nonce": nonce.hex(),
        "ciphertext": ciphertext.hex(),
        "hmac_tag": hmac_tag,
        "encryption": "ChaCha20-Poly1305",
        "integrity": "SHA-256",
        "authentication": "HMAC-SHA256",
        "status": "SECURE",
    })


@app.route("/api/decrypt", methods=["POST"])
@login_required
def api_decrypt():
    user = current_user()
    username = user["username"]
    bundle = get_bundle(user["id"])   # only THIS user's bundle
    if bundle is None:
        return jsonify({"error": "No encrypted data found. Encrypt something first."}), 400

    # Check 0 (no password needed): has the stored data been modified?
    if not bundle_is_intact(bundle):
        log("TAMPER DETECTED - stored data modified, decryption blocked", username)
        return jsonify({"success": False, "tampered": True})

    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if not isinstance(password, str) or not password:
        return jsonify({"error": "Please enter your encryption password."}), 400

    throttle_key = ("decrypt", user["id"])
    if is_blocked(throttle_key):
        return jsonify({"error": "Too many failed attempts. Please wait a few minutes."}), 429

    def failed():
        record_failure(throttle_key)
        log("DECRYPTION FAILED", username)
        return jsonify({"success": False, "tampered": False, "message": GENERIC_FAIL})

    salt, nonce, ciphertext = bundle["salt"], bundle["nonce"], bundle["ciphertext"]
    enc_key, auth_key = derive_keys_from_password(password, salt)
    aad = aad_for(user, salt)
    steps = []

    # Step 1: HMAC-SHA256 envelope check
    envelope = build_envelope(nonce, ciphertext, aad + FILENAME_TAG)
    if not verify_hmac(auth_key, envelope, bundle["hmac_tag"]):
        return failed()
    steps.append({"label": "HMAC-SHA256 envelope check", "ok": True})

    # Step 2: ChaCha20-Poly1305 decrypt + built-in tag check
    try:
        plaintext = decrypt(ciphertext, enc_key, nonce, aad)
    except Exception:
        return failed()
    steps.append({"label": "ChaCha20-Poly1305 tag check", "ok": True})

    # Step 3: final SHA-256 integrity check
    if sha256_hash(plaintext) != bundle["sha256_hash"]:
        return failed()
    steps.append({"label": "SHA-256 final integrity check", "ok": True})

    clear_failures(throttle_key)
    log("DECRYPTION SUCCESS", username)
    return jsonify({"steps": steps, "success": True, "plaintext": plaintext.decode(errors="replace")})


@app.route("/api/tamper", methods=["POST"])
@login_required
def api_tamper():
    user = current_user()
    bundle = get_bundle(user["id"])
    if bundle is None:
        return jsonify({"error": "No encrypted data to tamper with. Encrypt something first."}), 400

    tampered = bytearray(bundle["ciphertext"])
    tampered[0] ^= 0xFF
    update_ciphertext(user["id"], bytes(tampered))
    log("TAMPER TEST - flipped first byte of stored ciphertext", user["username"])

    # Real detection: re-check the stored bundle against its fingerprint
    detected = not bundle_is_intact(get_bundle(user["id"]))
    if detected:
        log("TAMPER DETECTED", user["username"])
    return jsonify({"ciphertext": bytes(tampered).hex(), "tamper_detected": detected})


@app.route("/api/log")
@login_required
def api_log():
    return jsonify({"lines": read_log(current_user()["username"])})


if __name__ == "__main__":
    # Debug mode exposes an interactive debugger: only enable it with FLASK_DEBUG=1
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
