import sqlite3
from os import path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from enums import ServerErrCode


def public_key_response(public_key: rsa.RSAPublicKey):
    pubkey_bytes = public_key.public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH
    )
    response = {
        "success": True,
        "data": pubkey_bytes.decode()
    }
    return response


def initialize_database(db_filename, schema_command):
    if path.exists(db_filename):
        print("Found existing database. Loading from there.")
        database = sqlite3.connect(db_filename)
        cursor = database.cursor()
    else:
        print("No database found. Initializing new database from schema...")
        database = sqlite3.connect(db_filename)
        cursor = database.cursor()
        cursor.executescript(schema_command)
        database.commit()

    enable_foreign_keys = "PRAGMA foreign_keys = 1"
    cursor.execute(enable_foreign_keys)
    cursor.close()
    return database


def bad_request_json(err: ServerErrCode, comment: str = None):
    return {
        "success": False,
        "data": err,
        "comment": comment,
    }
