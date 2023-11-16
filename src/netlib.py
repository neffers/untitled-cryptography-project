import base64
import json
import socket


def get_dict_from_socket(sock: socket.socket) -> dict:
    buf_len = sock.recv(4)
    buf_len = int.from_bytes(buf_len, 'big', signed=False)
    raw_json = sock.recv(buf_len)
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
