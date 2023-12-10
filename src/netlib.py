import base64
import json
import socket

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPrivateKey


def get_dict_from_socket(sock: socket.socket) -> dict:
    buf_len = sock.recv(4)
    if buf_len == b'':
        raise BrokenPipeError
    buf_len = int.from_bytes(buf_len, 'big', signed=False)
    raw_json = sock.recv(buf_len)
    if raw_json == b'':
        raise BrokenPipeError
    to_return = None
    try:
        to_return = json.loads(raw_json)
    except json.decoder.JSONDecodeError:
        print("Could not interpret packet. Len: {} Received: {}".format(buf_len, raw_json))
    return to_return


def send_dict_to_socket(packet: dict, sock: socket.socket):
    dict_bytes = json.dumps(packet).encode()
    length = len(dict_bytes)
    buffer = length.to_bytes(4, 'big', signed=False) + dict_bytes
    sock.sendall(buffer)


def bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, 'big')


def int_to_bytes(i: int) -> bytes:
    return i.to_bytes(32, 'big')


def bytes_to_b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def b64_to_bytes(s: str) -> bytes:
    return base64.b64decode(s)


def serialize_public_key(key: RSAPublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH)


def deserialize_public_key(data: bytes) -> RSAPublicKey:
    return serialization.load_ssh_public_key(data)


def serialize_private_key(key: RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption())


def deserialize_private_key(data: bytes) -> RSAPrivateKey:
    return serialization.load_ssh_private_key(data, None)
