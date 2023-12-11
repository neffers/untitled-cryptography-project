import json
from os import urandom, path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_pad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

import netlib


def initialize_key(key_filename):
    if path.exists(key_filename):
        print("Found existing private key, using that.")
        with open(key_filename, "rb") as key_file:
            key: rsa.RSAPrivateKey = netlib.deserialize_private_key(key_file.read())
    else:
        print("No existing private key found, generating...")
        key = rsa.generate_private_key(65537, 4096)
        to_write = netlib.serialize_private_key(key)
        with open(key_filename, "wb") as key_file:
            key_file.write(to_write)
    print("Key Hash: " + public_key_hash(key.public_key()))
    return key

def generate_rsa_key():
    return rsa.generate_private_key(65537, 4096)

def public_key_hash(key: rsa.RSAPublicKey):
    public_key_bytes = netlib.serialize_public_key(key)
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update(public_key_bytes)
    return netlib.bytes_to_b64(hasher.finalize())


def rsa_decrypt(key: rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    return key.decrypt(ciphertext, asym_pad.OAEP(asym_pad.MGF1(hashes.SHA256()), hashes.SHA256(), None))


def rsa_encrypt(key: rsa.RSAPublicKey, message: bytes) -> bytes:
    return key.encrypt(message, asym_pad.OAEP(asym_pad.MGF1(hashes.SHA256()), hashes.SHA256(), None))


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
    assert len(key) == 32  # AES keys should be 256 bits
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    aes = Cipher(algorithms.AES(key), modes.CBC(iv))
    unpad = padding.PKCS7(128).unpadder()
    decryptor = aes.decryptor()
    decrypted_payload = decryptor.update(ciphertext) + decryptor.finalize()
    unpadded = unpad.update(decrypted_payload) + unpad.finalize()
    return unpadded


def decrypt_dict(key: bytes, ciphertext: bytes) -> dict:
    decrypted = symmetric_decrypt(key, ciphertext)
    return json.loads(decrypted.decode())


def symmetric_encrypt(key: bytes, message: bytes) -> bytes:
    assert len(key) == 32  # AES keys should be 256 bits
    iv = urandom(16)
    aes = Cipher(algorithms.AES(key), modes.CBC(iv))
    pad = padding.PKCS7(128).padder()
    encryptor = aes.encryptor()
    padded = pad.update(message) + pad.finalize()
    encrypted = encryptor.update(padded) + encryptor.finalize()
    return iv + encrypted


def encrypt_dict(key: bytes, message: dict) -> bytes:
    to_encrypt = json.dumps(message).encode()
    return symmetric_encrypt(key, to_encrypt)

