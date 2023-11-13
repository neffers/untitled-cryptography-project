from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa


def public_key_hash(key: rsa.RSAPublicKey):
    public_key_bytes = key.public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH
    )
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(public_key_bytes)
    return hasher.finalize().hex()
