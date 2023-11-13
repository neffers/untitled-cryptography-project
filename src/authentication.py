import base64
import socketserver
import signal
import sys
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as apad

from enums import AuthRequestType
import netlib
import serverlib
import cryptolib


def get_token_response(request: dict):
    rsa_encrypted_aes_key = base64.b64decode(request["encrypted_key"])
    signin_payload = base64.b64decode(request["signin_payload"])
    aes_key = cryptolib.rsa_decrypt(private_key, rsa_encrypted_aes_key)
    signin_request = cryptolib.decrypt_dict(aes_key, signin_payload)
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
        token = cryptolib.rsa_sign_string(private_key, identity)
        encrypted_token = cryptolib.symmetric_encrypt(aes_key, token)
        response = {
            "success": True,
            "data": netlib.bytes_to_b64(encrypted_token)
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
        print("socket opened with {}".format(self.client_address[0]))
        request = netlib.get_dict_from_socket(self.request)
        print("received {}".format(request))
        response = generate_response(request)
        print("sending {}".format(response))
        netlib.send_dict_to_socket(response, self.request)
        print("closing socket with {}".format(self.client_address[0]))


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

    public_key_file = "auth_public_key"
    public_key_writable = public_key.public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH
    )
    with open(public_key_file, "wb") as key_file:
        key_file.write(public_key_writable)

    signal.signal(signal.SIGINT, signal_handler)

    try:
        server = socketserver.TCPServer((HOST, PORT), Handler)
        print("socket bound successfully")
        server.serve_forever()
    except OSError:
        print("can't bind to " + HOST + ":" + str(PORT))
