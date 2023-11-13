import json
from os import urandom

from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_pad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def public_key_hash(key: rsa.RSAPublicKey):
    public_key_bytes = key.public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH
    )
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(public_key_bytes)
    return hasher.finalize().hex()


def rsa_decrypt(key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    return key.decrypt(ciphertext, asym_pad.OAEP(asym_pad.MGF1(hashes.SHA256()), hashes.SHA256(), None))


def symmetric_decrypt(key: bytes, ciphertext: bytes) -> bytes:
    aes = Cipher(algorithms.AES(key), modes.CBC(urandom(16)))
    unpad = padding.PKCS7(128).unpadder()
    decryptor = aes.decryptor()
    decrypted_payload = decryptor.update(ciphertext) + decryptor.finalize()
    unpadded = unpad.update(decrypted_payload) + unpad.finalize()
    return unpadded


def decrypt_dict(key: bytes, ciphertext: bytes) -> dict:
    decrypted = symmetric_decrypt(key, ciphertext)
    return json.loads(decrypted.decode())


def symmetric_encrypt(key: bytes, message: bytes) -> bytes:
    aes = Cipher(algorithms.AES(key), modes.CBC(urandom(16)))
    pad = padding.PKCS7(128).padder()
    encryptor = aes.encryptor()
    padded = pad.update(message) + pad.finalize()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return encrypted


def encrypt_dict(key: bytes, message: dict) -> bytes:
    to_encrypt = json.dumps(message).encode()
    return symmetric_encrypt(key, to_encrypt)
