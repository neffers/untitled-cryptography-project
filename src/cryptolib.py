import json
from os import urandom

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_pad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import netlib


def public_key_hash(key: rsa.RSAPublicKey):
    public_key_bytes = key.public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH
    )
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(public_key_bytes)
    return netlib.bytes_to_b64(hasher.finalize())


def rsa_decrypt(key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    return key.decrypt(ciphertext, asym_pad.OAEP(asym_pad.MGF1(hashes.SHA256()), hashes.SHA256(), None))


def rsa_sign(key: rsa.RSAPrivateKey, message: bytes) -> bytes:
    sign_pad = asym_pad.PSS(asym_pad.MGF1(hashes.SHA256()), asym_pad.PSS.MAX_LENGTH)
    return key.sign(message, sign_pad, hashes.SHA256())


def rsa_sign_string(key: rsa.RSAPrivateKey, message: str) -> bytes:
    return rsa_sign(key, message.encode())


def rsa_verify(key: rsa.RSAPublicKey, signature: bytes, message: bytes) -> bool:
    sign_pad = asym_pad.PSS(asym_pad.MGF1(hashes.SHA256()), asym_pad.PSS.MAX_LENGTH)
    try:
        key.verify(signature, message, sign_pad, hashes.SHA256())
    except InvalidSignature:
        return False
    return True


def rsa_verify_str(key: rsa.RSAPublicKey, signature: bytes, message: str) -> bool:
    return rsa_verify(key, signature, message.encode())


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
