import socketserver
import json
import struct
import signal
import sys
import sqlite3
from os import path
from enums import AuthRequestType


def response_token(token):
    return {"type": token, "token": token}

def initialize_database():
    if path.exists(db_filename):
        print("Found existing database. Loading from there.")
        db = sqlite3.connect(db_filename)
    else:
        print("No database found. Initializing new database from schema...")
        db = sqlite3.connect(db_filename)
        cursor = db.cursor()

        db_init_command = """
        CREATE TABLE users (
            identity TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        );
        """
        cursor.execute(db_init_command)
        cursor.close()
    return db


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
            response = response_token(request["identity"])
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
    db_filename = "auth_db"
    db = initialize_database()
    signal.signal(signal.SIGINT, signal_handler)
    try:
        server = socketserver.TCPServer((HOST, PORT), Handler)
        print("socket bound successfully")
        server.serve_forever()
    except OSError:
        print("can't bind to " + HOST + ":" + str(PORT))
