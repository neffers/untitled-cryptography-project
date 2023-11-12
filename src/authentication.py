import base64
import socketserver
import json
import struct
import signal
import sys
import serverlib
from os import urandom
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as apad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from enums import AuthRequestType


def get_token_response(request: dict):
    rsa_encrypted_aes_key = base64.b64decode(request["encrypted_key"])
    signin_payload = base64.b64decode(request["signin_payload"])
    aes_key = private_key.decrypt(
        rsa_encrypted_aes_key,
        apad.OAEP(
            apad.MGF1(hashes.SHA256()),
            hashes.SHA256(),
            None
        )
    )
    aes = Cipher(algorithms.AES(aes_key), modes.CBC(urandom(16)))
    symmetric_pad = padding.PKCS7(128)
    pad = symmetric_pad.padder()
    unpad = symmetric_pad.unpadder()
    encryptor = aes.encryptor()
    decryptor = aes.decryptor()
    decrypted_payload = decryptor.update(signin_payload) + decryptor.finalize()
    unpadded = unpad.update(decrypted_payload) + unpad.finalize()
    signin_request = json.loads(unpadded.decode())
    identity = signin_request["identity"]
    password = signin_request["password"]

    get_user_command = """
        select identity, password
        from main.users
        where identity = ?
    """
    get_user_params = (identity,)
    cursor = db.cursor()
    cursor.execute(get_user_command, get_user_params)
    try:
        (db_id, db_pw) = cursor.fetchone()
    except TypeError:  # user not in db
        add_user_command = "insert into users(identity, password) values(?,?)"
        add_user_params = (identity, password)
        cursor.execute(add_user_command, add_user_params)
        cursor.close()
        db.commit()
        (db_id, db_pw) = (identity, password)
    if not db_pw == password:
        response = {
            "success": False,
            "data": "Password did not match",
        }
    else:
        sign_pad = apad.PSS(apad.MGF1(hashes.SHA256()), apad.PSS.MAX_LENGTH)
        token = private_key.sign(bytes(identity), sign_pad, hashes.SHA256())
        padded_token = pad.update(token) + pad.finalize()
        encrypted_token = encryptor.update(padded_token) + encryptor.finalize()
        response = {
            "success": True,
            "data": base64.b64encode(encrypted_token).decode()
        }
    return response


def generate_response(request: dict):
    if request["type"] == AuthRequestType.Token:
        return get_token_response(request)
    elif request["type"] == AuthRequestType.PublicKey:
        return serverlib.public_key_response(public_key)
    else:
        return {
            "success": False,
            "data": "Bad request, not in AuthRequestType"
        }


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        print("handling packet")
        self.data = self.request.recv(4)
        buffer_len = struct.unpack("!I", self.data)[0]
        self.data = self.request.recv(buffer_len)
        print("data received")
        print("received {} from {}".format(self.data, self.client_address[0]))
        try:
            request = json.loads(self.data)
            response = generate_response(request)
            print("sending {}".format(response))
            response = json.dumps(response).encode()
        except json.decoder.JSONDecodeError:
            print("Could not interpret packet!")
            response = {"success": False, "data": "Malformed request!"}

        buffer = struct.pack("!I", len(response))
        buffer += bytes(response)
        self.request.send(buffer)


def signal_handler(sig, frame):
    print("\nshutting down...")
    server.server_close()
    sys.exit(0)


if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 8085

    db_location = "auth_db"
    db_init_command = """
    CREATE TABLE users (
        identity TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    );
    """
    db = serverlib.initialize_database(db_location, db_init_command)

    private_key_file = "auth_private_key"
    private_key: rsa.RSAPrivateKey = serverlib.initialize_key(private_key_file)
    public_key = private_key.public_key()

    signal.signal(signal.SIGINT, signal_handler)

    try:
        server = socketserver.TCPServer((HOST, PORT), Handler)
        print("socket bound successfully")
        server.serve_forever()
    except OSError:
        print("can't bind to " + HOST + ":" + str(PORT))
