import base64
import os
import re
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature

_LICENSE_FILE = Path.home() / ".helmgate" / "license"
_KEY_PATTERN = re.compile(r"^HGATE-[A-Za-z0-9_-]{10,}$")

# Public key only — safe to ship in open source.
_PUBLIC_KEY_PEM = b"""-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEw1VD4zF0z2qMQTMmrVh3ViG2xiKt
dC3SHCrI1smn1dQWAvyg/tHWio97q/W2TXwMTvZm9JP6C4SO15b+IsD6cw==
-----END PUBLIC KEY-----"""

_public_key = serialization.load_pem_public_key(_PUBLIC_KEY_PEM)


def validate_key(key: str) -> bool:
    """Return True if the key has a valid ECDSA signature."""
    if not _KEY_PATTERN.match(key):
        return False
    try:
        payload = base64.urlsafe_b64decode(key[6:] + "==")  # strip "HGATE-"
        nonce, signature = payload[:8], payload[8:]
        _public_key.verify(signature, nonce, ec.ECDSA(hashes.SHA256()))
        return True
    except (InvalidSignature, Exception):
        return False


def get_license_key() -> str | None:
    """Return the license key from env var or license file, or None if not set."""
    key = os.environ.get("HELMGATE_LICENSE_KEY", "").strip()
    if key:
        return key
    if _LICENSE_FILE.exists():
        return _LICENSE_FILE.read_text().strip()
    return None


def is_pro() -> bool:
    """Return True if a valid Pro license key is present."""
    key = get_license_key()
    return key is not None and validate_key(key)


def activate(key: str) -> bool:
    """Save a valid license key to the license file. Returns True on success."""
    if not validate_key(key):
        return False
    _LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _LICENSE_FILE.write_text(key)
    return True
