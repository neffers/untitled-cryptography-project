import sqlite3
from os import path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import src.cryptolib
import src.netlib


def public_key_response(public_key: rsa.RSAPublicKey):
    pubkey_bytes = public_key.public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH
    )
    response = {
        "success": True,
        "data": src.netlib.bytes_to_b64(pubkey_bytes)
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


def initialize_key(key_filename):
    if path.exists(key_filename):
        print("Found existing private key, using that.")
        with open(key_filename, "rb") as key_file:
            key: rsa.RSAPrivateKey = serialization.load_ssh_private_key(
                key_file.read(),
                None
            )
    else:
        print("No existing private key found, generating...")
        key = rsa.generate_private_key(65537, 4096)
        to_write = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption()
        )
        with open(key_filename, "wb") as key_file:
            key_file.write(to_write)
    print("Key Hash: " + src.cryptolib.public_key_hash(key.public_key()))
    return key
