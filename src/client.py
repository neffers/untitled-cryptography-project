import json
import socket
import base64
from datetime import datetime
from typing import Union

from cryptography.hazmat.primitives.asymmetric import rsa

import os
import netlib
import cryptolib
from enums import AuthRequestType, ResourceRequestType, Permissions, ServerErrCode

identity: str = ""
token: bytes = bytes()
sock: socket.socket = socket.socket()
session_key: bytes = bytes()
seqnum: int
key_filename = str()
private_key: rsa.RSAPrivateKey
rs_pub: rsa.RSAPublicKey
counter = 0

# formatting lookup tables
perms = ["No Access", "Read Access", "Write Access", "Mod", "Admin"]
bools = ["False", "True"]


def print_err(err_type):
    if err_type == ServerErrCode.AuthenticationFailure:
        print("Error: Authentication failed!")
    if err_type == ServerErrCode.DoesNotExist:
        print("Error: The desired data does not exist!")
    if err_type == ServerErrCode.InsufficientPermission:
        print("Error: You do not have permission to run this command!")
    if err_type == ServerErrCode.MalformedRequest:
        print("Error: Request was incorrectly formatted!")
    if err_type == ServerErrCode.SessionExpired:
        print("Error: The current session has expired!")


def decrypt_read_resource(keys, key_ver, resource) -> Union[bytes, None]:
    for key in keys["data"]["read"]:
        version = key[0]
        key = key[1]
        if version == key_ver:
            key = cryptolib.rsa_decrypt(private_key, key)
            resource = cryptolib.symmetric_decrypt(key, resource)
            return resource
    return None


def decrypt_uploader_resource(uploader_key, resource) -> bytes:
    key = cryptolib.rsa_decrypt(private_key, uploader_key)
    return cryptolib.symmetric_decrypt(key, resource)


def decrypt_mod_resource(keys, mod_key, mod_key_ver, resource) -> Union[bytes, None]:
    for key in keys["data"]["mod"]:
        version = key[0]
        priv = key[1]
        sym = key[2]
        if version == mod_key_ver:
            sym = cryptolib.rsa_decrypt(private_key, sym)
            priv = cryptolib.symmetric_decrypt(sym, priv)
            key = cryptolib.rsa_decrypt(netlib.deserialize_private_key(priv), mod_key)
            return cryptolib.symmetric_decrypt(key, resource)
    return None


class Request:
    def __init__(self, request: dict):
        self.request = request

    def make_request(self) -> dict:
        global seqnum
        request = self.request
        request["seqnum"] = seqnum
        encrypted_bytes = cryptolib.encrypt_dict(session_key, request)
        signature = cryptolib.rsa_sign(private_key, encrypted_bytes)
        base64_request = netlib.bytes_to_b64(encrypted_bytes)
        base64_signature = netlib.bytes_to_b64(signature)
        encrypted_request = {"encrypted_request": base64_request,
                             "signature": base64_signature}
        netlib.send_dict_to_socket(encrypted_request, sock)
        seqnum += 1
        dict_response = netlib.get_dict_from_socket(sock)
        if dict_response.get("encrypted_response") is None:
            # handle plaintext timeout message
            if dict_response.get("success") is not None and dict_response.get(
                    "data") == ServerErrCode.SessionExpired:
                return dict_response

        # handle bad signature
        if not cryptolib.rsa_verify(rs_pub, netlib.b64_to_bytes(dict_response.get("signature")),
                                    netlib.b64_to_bytes(dict_response.get("encrypted_response"))):
            response = {
                "success": False,
                "data": "Invalid signature"
            }
            return response

        # handle bad seqnum
        response = cryptolib.decrypt_dict(session_key, netlib.b64_to_bytes(dict_response["encrypted_response"]))
        if response["seqnum"] != seqnum:
            response = {
                "success": False,
                "data": "Incorrect seqnum"
            }
            return response
        seqnum += 1
        return response

    def safe_print(self, response: dict) -> None:
        if response is None or "success" not in response or "data" not in response:
            print("Malformed packet: " + str(response))
            return
        if response["success"]:
            self.print_response(response)
        else:
            print_err(response["data"])

    def print_response(self, response):
        print("Operation successful.")


# Auth server request
def request_token(as_sock, password, as_pub) -> Union[dict, None]:
    aes_key = os.urandom(32)
    encrypted_key = cryptolib.rsa_encrypt(as_pub, aes_key)
    signin_dict = {
        "identity": identity,
        "password": password,
        "rs_keyhash": cryptolib.public_key_hash(rs_pub),
    }
    signin_payload = cryptolib.encrypt_dict(aes_key, signin_dict)
    request = {
        "type": AuthRequestType.Token,
        "encrypted_key": netlib.bytes_to_b64(encrypted_key),
        "signin_payload": netlib.bytes_to_b64(signin_payload),
    }
    netlib.send_dict_to_socket(request, as_sock)
    response = netlib.get_dict_from_socket(as_sock)
    if "success" in response:
        if response["success"]:
            return cryptolib.decrypt_dict(aes_key, netlib.b64_to_bytes(response["data"]))

    return None


# Auth server request
def request_pub_key() -> Union[rsa.RSAPublicKey, None]:
    request = {
        "type": AuthRequestType.PublicKey,
    }
    netlib.send_dict_to_socket(request, sock)
    response = netlib.get_dict_from_socket(sock)
    if "success" in response and response["success"]:
        return netlib.deserialize_public_key(response["data"].encode())

    return None


class ShowLeaderboardsRequest(Request):
    def __init__(self):
        super().__init__({
            "type": ResourceRequestType.ListLeaderboards
        })

    def print_response(self, response: dict) -> None:
        print("{:<4}{:<21.21}{:<6}".format("ID", "Leaderboard Name", "Permission"))
        for ldb in response["data"]:
            print("{:<4}{:<21.21}{:<6}".format(ldb[0], ldb[1], perms[ldb[2]]))


class CreateLeaderboardRequest(Request):
    def __init__(self, leaderboard_name, leaderboard_ascending, mod_pubkey, read_key, mod_sym, mod_priv):
        super().__init__({
            "type": ResourceRequestType.CreateLeaderboard,
            "leaderboard_name": leaderboard_name,
            "leaderboard_ascending": leaderboard_ascending,
            "mod_pubkey": mod_pubkey,
            "read_key": read_key,
            "mod_sym": mod_sym,
            "mod_priv": mod_priv
        })

    def print_response(self, response):
        print("New Leaderboard ID: {}".format(response["data"]))


class AddEntryRequest(Request):
    def __init__(self, leaderboard_id, score, comment, user_key, mod_key, mod_key_ver):
        super().__init__({
            "type": ResourceRequestType.AddEntry,
            "leaderboard_id": leaderboard_id,
            "score": score,
            "comment": comment,
            "user_key": user_key,
            "mod_key": mod_key,
            "mod_key_ver": mod_key_ver
        })

    def print_response(self, response):
        print("New Entry ID: {}".format(response["data"]))


class AccessGroupsRequest(Request):
    def __init__(self, leaderboard_id):
        super().__init__({
            "type": ResourceRequestType.ListAccessGroups,
            "leaderboard_id": leaderboard_id,
        })

    def print_response(self, response):
        print("{:<4}{:<21}{:<11}".format("ID", "Name", "Permission"))
        for user in response["data"]:
            print("{:<4}{:<21}{:<11}".format(user[0], user[1], user[2]))


class SetScoreOrderRequest(Request):
    def __init__(self, leaderboard_id, ascending):
        super().__init__({
            "type": ResourceRequestType.ChangeScoreOrder,
            "leaderboard_id": leaderboard_id,
            "ascending": ascending
        })


class ListUsersRequest(Request):
    def __init__(self):
        super().__init__({
            "type": ResourceRequestType.ListUsers
        })

    def print_response(self, response):
        print("{:<4}{:<21.21}".format("ID", "Username"))
        for user in response["data"]:
            print("{:<4}{:<21.21}".format(user[0], user[1]))


class ListUnverifiedRequest(Request):
    def __init__(self, leaderboard_id):
        super().__init__({
            "type": ResourceRequestType.ListUnverified,
            "leaderboard_id": leaderboard_id
        })

    def print_response(self, response):
        print("{:<9}{:<8}{:<21.21}{:<20}".format("Entry ID", "User ID", "Username", "Date"))
        for entry in response["data"]:
            date = datetime.fromtimestamp(entry[3])
            print("{:<9}{:<8}{:<21.21}{:<20}".format(entry[0], entry[1], entry[2], str(date)))


class GetEntryRequest(Request):
    def __init__(self, entry_id):
        super().__init__({
            "type": ResourceRequestType.GetEntry,
            "entry_id": entry_id
        })

    def print_response(self, response):
        """ shape of response
            entry:
                0 entry id
                1 leaderboard id
                2 user id
                3 identity
                4 score
                5 date
                6 uploader key
                7 mod key
                8 mod key ver
                9 read key ver
                10 verified
                11 verifier id
                12 verifier identity
                13 verification date
            comments:
                0 identity
                1 date
                2 content
                3 uploader key
                4 mod key
                5 mod key ver
                6 read key ver
            files:
                0 file id
                1 file name
                2 submission_date
                3 uploader key
                4 mod key
                5 mod key ver
                6 read key ver
        """
        entry = response["data"]["entry"]
        entry_id = entry[0]
        entry_user_id = entry[2]
        entry_identity = entry[3]
        entry_date = entry[5]
        entry_verified = entry[10]
        entry_mod_id = entry[11]
        entry_mod_identity = entry[12]
        leaderboard_id = entry[1]
        user_id = do_get_self_id()
        keys = do_get_keys(user_id, leaderboard_id)
        score = entry[4]
        verified = entry[10]
        if verified:
            read_key_ver = entry[9]
            score = netlib.bytes_to_int(decrypt_read_resource(keys, read_key_ver, score))
        else:
            if identity == entry_identity:
                uploader_key = entry[6]
                score = netlib.bytes_to_int(decrypt_uploader_resource(uploader_key, score))
            else:
                mod_key = entry[7]
                mod_key_ver = entry[8]
                score = netlib.bytes_to_int(decrypt_mod_resource(keys, mod_key, mod_key_ver, score))
        if not isinstance(score, int):
            print("failed to decrypt")
            return

        print("{:<9}{:<8}{:<21.21}{:<15}{:<20}{:<9}{:<7}{:<21.21}"
              .format("Entry ID", "User ID", "Username", "Score", "Date", "Verified", "Mod ID", "Mod Name"))
        date = datetime.fromtimestamp(entry_date)
        mod_id = entry_mod_id if entry_mod_id else "N/A"
        mod_name = entry_mod_identity if entry_mod_identity else "N/A"
        print("{:<9}{:<8}{:<21.21}{:<15}{:<20}{:<9}{:<7}{:<21.21}"
              .format(entry_id, entry_user_id, entry_identity, score, str(date), bools[entry_verified], mod_id,
                      mod_name))
        comments = response["data"]["comments"]
        print("{} Comments".format(len(comments)))
        files = response["data"]["files"]
        print("{:<4}{:<21.21}{:<20}"
              .format("ID", "Filename", "Date"))
        for file in files:
            date = datetime.fromtimestamp(file[2])
            print("{:<4}{:<21.21}{:<20}"
                  .format(file[0], file[1], str(date)))


class AddProofRequest(Request):
    def __init__(self, entry_id, filename, blob, uploader_key, mod_key, mod_key_ver):
        super().__init__({
            "type": ResourceRequestType.AddProof,
            "entry_id": entry_id,
            "filename": filename,
            "file": base64.b64encode(blob).decode(),
            "uploader_key": uploader_key,
            "mod_key": mod_key,
            "mod_key_ver": mod_key_ver
        })


class GetProofRequest(Request):
    def __init__(self, file_id):
        super().__init__({
            "type": ResourceRequestType.DownloadProof,
            "file_id": file_id
        })


class RemoveProofRequest(Request):
    def __init__(self, file_id):
        super().__init__({
            "type": ResourceRequestType.RemoveProof,
            "file_id": file_id
        })


class ViewUserRequest(Request):
    def __init__(self, user_id):
        super().__init__({
            "type": ResourceRequestType.ViewUser,
            "user_id": user_id
        })

    def print_response(self, response):
        user_data = response["data"]["user_data"]
        entries = response["data"]["entries"]
        date = datetime.fromtimestamp(user_data[1])
        print("Name: {} Registration Date: {}".format(user_data[0], str(date)))
        print("{:<4}{:<5}{:<9}{:<20}"
              .format("ID", "LB ID", "Verified", "Registration Date"))
        for entry in entries:
            date = datetime.fromtimestamp(entry[3])
            print("{:<4}{:<5}{:<9}{:<20}"
                  .format(entry[0], entry[1], bools[entry[2]], str(date)))


class OneLeaderboardRequest(Request):
    def __init__(self, leaderboard_id):
        super().__init__({
            "type": ResourceRequestType.ShowOneLeaderboard,
            "leaderboard_id": leaderboard_id
        })

    def print_response(self, response):
        """ shape of response
        entries: (if not mod)
            0 entry id
            1 user id
            2 user identity
            3 score
            4 submission_date
            5 verified
            6 read_key_ver
            7 uploader_key
        entries: (if mod)
            0 entry id
            1 user id
            2 user identity
            3 score
            4 submission_date
            5 verified
            6 read_key_ver
            7 mod_key
            8 mod_key_ver
        """
        entries = response["data"]["entries"]
        print("Leaderboard ID: {} Leaderboard Name: {}".format(response["data"]["id"], response["data"]["name"]))
        print("{:<9}{:<8}{:<21.21}{:<15}{:<20}{:<6}"
              .format("Entry ID", "User ID", "Username", "Score", "Date", "Verified"))
        if entries.len() == 0:
            print("No entries found")
            return
        is_mod = entries[0].len() == 7  # returns a different set of columns if client is moderator
        leaderboard_id = self.request["leaderboard_id"]
        user_id = do_get_self_id()
        keys = do_get_keys(user_id, leaderboard_id)
        for entry in entries:
            entry_id = entry[0]
            entry_user_id = entry[1]
            entry_identity = entry[2]
            entry_score = entry[3]
            entry_date = entry[4]
            entry_verified = entry[5]
            read_key_ver = entry[6]
            if entry_verified:
                entry_score = netlib.bytes_to_int(decrypt_read_resource(keys, read_key_ver, entry_score))
            else:
                if identity == entry_identity and not is_mod:
                    uploader_key = entry[7]
                    entry_score = netlib.bytes_to_int(decrypt_uploader_resource(uploader_key, entry_score))
                elif is_mod:
                    mod_key = entry[7]
                    mod_key_ver = entry[8]
                    entry_score = netlib.bytes_to_int(decrypt_mod_resource(keys, mod_key, mod_key_ver, entry_score))
            if not isinstance(entry_score, int):
                print("failed to decrypt")
                return
            date = datetime.fromtimestamp(entry_date)
            print("{:<9}{:<8}{:<21.21}{:<15}{:<20}{:<6}"
                  .format(entry_id, entry_user_id, entry_identity, entry_score, str(date), bools[entry_verified]))


class ViewPermissionsRequest(Request):
    def __init__(self, user_id):
        super().__init__({
            "type": ResourceRequestType.ViewPermissions,
            "user_id": user_id
        })

    def print_response(self, response):
        print("{:<5}{:<12}".format("LB ID", "Permission"))
        for permission in response["data"]:
            print("{:<5}{:<12}".format(permission[0], perms[permission[1]]))


class VerifyEntryRequest(Request):
    def __init__(self, entry_id, read_key_ver):
        super().__init__({
            "type": ResourceRequestType.VerifyEntry,
            "entry_id": entry_id,
            "read_key_ver": read_key_ver
        })


class RemoveLeaderboardRequest(Request):
    def __init__(self, leaderboard_id):
        super().__init__({
            "type": ResourceRequestType.RemoveLeaderboard,
            "leaderboard_id": leaderboard_id
        })


class AddCommentRequest(Request):
    def __init__(self, entry_id, content, uploader_key, mod_key, mod_key_ver):
        super().__init__({
            "type": ResourceRequestType.AddComment,
            "entry_id": entry_id,
            "content": content,
            "uploader_key": uploader_key,
            "mod_key": mod_key,
            "mod_key_ver": mod_key_ver
        })


class RemoveEntryRequest(Request):
    def __init__(self, entry_id):
        super().__init__({
            "type": ResourceRequestType.RemoveEntry,
            "entry_id": entry_id
        })


class AddPermissionRequest(Request):
    def __init__(self, user_id, leaderboard_id, permission, read_keys, mod_keys):
        super().__init__({
            "type": ResourceRequestType.AddPermission,
            "user_id": user_id,
            "leaderboard_id": leaderboard_id,
            "permission": permission,
            "read_keys": read_keys,
            "mod_keys": mod_keys
        })


class RemovePermissionRequest(Request):
    def __init__(self, user_id, leaderboard_id, new_read_keys, new_mod_keys, new_mod_pubkey):
        super().__init__({
            "type": ResourceRequestType.RemovePermission,
            "user_id": user_id,
            "leaderboard_id": leaderboard_id,
            "new_read_keys": new_read_keys,
            "new_mod_keys": new_mod_keys,
            "new_mod_pubkey": new_mod_pubkey
        })


class RemoveUserRequest(Request):
    def __init__(self, user_id):
        super().__init__({
            "type": ResourceRequestType.RemoveUser,
            "user_id": user_id
        })


class GetSelfIDRequest(Request):
    def __init__(self):
        super().__init__({
            "type": ResourceRequestType.GetSelfID,
            "user_id": identity
        })


class GetKeysRequest(Request):
    def __init__(self, user_id, leaderboard_id):
        super().__init__({
            "type": ResourceRequestType.GetKeys,
            "user_id": user_id,
            "leaderboard_id": leaderboard_id
        })


def do_get_keys(user_id, leaderboard_id) -> Union[dict, None]:
    request = GetKeysRequest(user_id, leaderboard_id)
    response = request.make_request()
    if "success" not in response or "data" not in response:
        print("Malformed packet: " + str(response))
        return None
    return response


def do_view_user(user_id):
    request = ViewUserRequest(user_id)
    request.safe_print(request.make_request())


def do_view_permissions(user_id):
    request = ViewPermissionsRequest(user_id)
    request.safe_print(request.make_request())


def do_add_permission(user_id):
    leaderboard_id = input("Enter the leaderboard id where the permission will be added: ")
    if not leaderboard_id.isdigit():
        print("Invalid input, please enter an integer")
        return
    leaderboard_id = int(leaderboard_id)
    permission = input(
        "[0] Read\n"
        "[1] Write\n"
        "[2] Moderator\n"
        "Select new permission level: ")
    if not permission.isdigit() or int(permission) > 3:
        print("Invalid input, please enter an integer listed above")
        return
    permission = int(permission)
    if permission == 0:
        permission = Permissions.Read
    elif permission == 1:
        permission = Permissions.Write
    elif permission == 2:
        permission = Permissions.Moderate
    request = AddPermissionRequest(user_id, leaderboard_id, permission)
    request.safe_print(request.make_request())


def do_remove_permission(user_id):
    leaderboard_id = input("Enter the leaderboard id where the permission will be added: ")
    if not leaderboard_id.isdigit():
        print("Invalid input, please enter an integer")
        return
    leaderboard_id = int(leaderboard_id)
    # get current read keys for leaderboard
    access_list = AccessGroupsRequest(leaderboard_id).make_request().get("data")
    user_data = [x for x in access_list if x[0] == user_id][0]
    user_perms = user_data[2]
    
    new_read_keys = {}

    new_mod_keys = None
    new_mod_privkey = None

    if user_perms >= Permissions.Moderate:
        new_mod_privkey = cryptolib.generate_rsa_key()
        new_mod_keys = {}

    new_read_key = os.urandom(32)
    for (user, _, _, pubkey) in access_list:
        encrypted_read_key = cryptolib.rsa_encrypt(pubkey, new_read_key)
        new_read_keys[user] = encrypted_read_key
        if user_perms >= Permissions.Moderate:
            priv_key_bytes = netlib.serialize_private_key(new_mod_privkey)
            mod_sym_key = os.urandom(32)
            encrypted_priv_key = cryptolib.symmetric_encrypt(mod_sym_key, priv_key_bytes) 
            new_mod_keys[user] = (cryptolib.rsa_encrypt(pubkey, mod_sym_key), encrypted_priv_key)

    if user_perms < Permissions.Moderate:
        request = RemovePermissionRequest(user_id, leaderboard_id, new_read_keys, None, None)
    else:
        request = RemovePermissionRequest(user_id, leaderboard_id, new_read_keys, new_mod_keys, 
                                          netlib.serialize_public_key(new_mod_privkey.public_key()))
    request.safe_print(request.make_request())


def do_remove_user(user_id):
    request = RemoveUserRequest(user_id)
    request.safe_print(request.make_request())


def user_options(user_id):
    while True:
        print(
            "User Commands:\n"
            "[0] Go Back\n"
            "[1] View User\n"
            "[2] View Permissions\n"
            "[3] Add Permission\n"
            "[4] Remove Permission\n"
            "[5] Open Submission\n"
            "[6] Remove User\n")
        choice = input("Choose the corresponding number: ")
        if not choice.isdigit() or int(choice) > 5:
            print("Invalid input, please enter an integer listed above")
            continue
        choice = int(choice)
        if choice == 0:
            break
        elif choice == 1:
            do_view_user(user_id)
        elif choice == 2:
            do_view_permissions(user_id)
        elif choice == 3:
            do_add_permission(user_id)
        elif choice == 4:
            do_remove_permission(user_id)
        elif choice == 5:
            entry_id = input("Enter the ID of the entry: ")
            try:
                entry_id = int(entry_id)
            except ValueError:
                print("Invalid entry ID")
                continue
            entry_options(entry_id)
        elif choice == 6:
            do_remove_user(user_id)
            return


def do_get_entry(entry_id):
    request = GetEntryRequest(entry_id)
    request.safe_print(request.make_request())


def do_add_proof(entry_id):
    # TODO encrypt
    filename = input("Enter name of local file to upload: ")
    try:
        with open(filename, 'rb') as file:
            blob = file.read()

            sym_key = os.urandom(32)
            uploader_key = cryptolib.rsa_encrypt(private_key.public_key(), sym_key)
            filename = cryptolib.symmetric_encrypt(sym_key, filename)
            blob = cryptolib.symmetric_encrypt(sym_key, blob)

            request = GetSelfIDRequest()
            reqrec = request.make_request()
            user_id = reqrec.get("data")

            request = GetEntryRequest(entry_id)
            reqrec = request.make_request()
            reqrec = reqrec.get("data")
            leaderboard_id = reqrec.get("leaderboard")

            request = GetKeysRequest(user_id, leaderboard_id)
            reqrec = request.make_request()
            reqrec = reqrec.get("data")
            
            mod_key_ver = reqrec.get("mod").len()
            mod_group_pub_key = reqrec.get("mod_pub")

            mod_key = cryptolib.rsa_encrypt(mod_group_pub_key, sym_key)

            request = AddProofRequest(entry_id, filename, blob, uploader_key, mod_key, mod_key_ver)
            request.safe_print(request.make_request())
    except FileNotFoundError:
        print("File not found!")
    except IOError:
        print("IO error occurred!")


def do_get_proof():
    remote_fileid = input("Enter id of remote file to download: ")
    if not remote_fileid.isdigit():
        print("Invalid input, please enter an integer")
        return
    remote_fileid = int(remote_fileid)
    local_filename = input("Enter name of local file to save it to: ")
    try:
        with open(local_filename, 'wb') as file:
            request = GetProofRequest(remote_fileid)
            response = request.make_request()
            if "success" not in response or "data" not in response:
                print("Malformed packet: " + str(response))
                return
            if response["success"]:
                """
                data:
                    "file"
                    "uploader_key"
                    "mod_key"
                    "mod_key_ver"
                    "read_key_ver"
                    "user_id"
                    "leaderboard"
                    "verified"
                """
                data = response["data"]["file"]
                client_id = do_get_self_id()
                keys = do_get_keys(client_id, response["data"]["leaderboard_id"])
                if response["data"]["verified"]:
                    data = decrypt_read_resource(keys, response["data"]["read_key_ver"], data)
                else:
                    if response["data"]["user_id"] == client_id:
                        data = decrypt_uploader_resource(response["data"]["uploader_key"], data)
                    else:
                        data = decrypt_mod_resource(keys, response["data"]["mod_key"], response["data"]["mod_key_ver"],
                                                    data)
                file.write(data)
                print("Operation successful.")
            else:
                print(response["data"])
    except FileNotFoundError:
        print("File not found!")
    except IOError:
        print("IO error occurred!")


def do_remove_proof():
    remote_fileid = input("Enter id of remote file to remove: ")
    if not remote_fileid.isdigit():
        print("Invalid input, please enter an integer")
        return
    remote_fileid = int(remote_fileid)
    request = RemoveProofRequest(remote_fileid)
    request.safe_print(request.make_request())


def do_view_comments(entry_id):
    request = GetEntryRequest(entry_id)
    response = request.make_request()
    if "success" not in response or "data" not in response:
        print("Malformed packet: " + str(response))
        return
    if response["success"]:
        comments = response["data"]["comments"]
        entry_verified = response["data"]["entry"][10]
        client_id = do_get_self_id()
        leaderboard_id = response["data"]["entry"][1]
        keys = do_get_keys(client_id, leaderboard_id)
        print("{:<21.21}{:<20}{}".format("Commenter", "Date", "Comment"))
        for comment in comments:
            """
                "comments"
                    0 poster's identity
                    1 date
                    2 content
                    3 uploader_key
                    4 mod_key
                    5 mod_key_ver
                    6 read_key_ver
            """
            date = datetime.fromtimestamp(comment[2])
            if entry_verified:
                comment_contents = decrypt_read_resource(keys, comment[6], comment[2])
            else:
                if comment[0] == identity:
                    comment_contents = decrypt_uploader_resource(comment[3], comment[2])
                else:
                    comment_contents = decrypt_mod_resource(keys, comment[4], comment[5], comment[2])
            print("{:<21.21}{:<20}{}".format(comment[1], str(date), comment_contents))
    else:
        print(response["data"])


def do_add_comment(entry_id):
    # TODO encrypt
    content = input("Enter your comment to the entry: ")

    sym_key = os.urandom(32)
    uploader_key = cryptolib.rsa_encrypt(private_key.public_key(), sym_key)
    content = cryptolib.symmetric_encrypt(sym_key, content)

    request = GetSelfIDRequest()
    reqrec = request.make_request()
    user_id = reqrec.get("data")

    request = GetEntryRequest(entry_id)
    reqrec = request.make_request()
    reqrec = reqrec.get("data")
    leaderboard_id = reqrec.get("leaderboard")

    request = GetKeysRequest(user_id, leaderboard_id)
    reqrec = request.make_request()
    reqrec = reqrec.get("data")
    
    mod_key_ver = reqrec.get("mod").len()
    mod_group_pub_key = reqrec.get("mod_pub")

    mod_key = cryptolib.rsa_encrypt(mod_group_pub_key, sym_key)

    request = AddCommentRequest(entry_id, content, uploader_key, mod_key, mod_key_ver)
    request.safe_print(request.make_request())


def do_verify_entry(entry_id):
    # TODO re encrypt

    request = GetSelfIDRequest()
    reqrec = request.make_request()
    user_id = reqrec.get("data")

    request = GetEntryRequest(entry_id)
    reqrec = request.make_request()
    reqrec = reqrec.get("data")
    leaderboard_id = reqrec.get("leaderboard")

    request = GetKeysRequest(user_id, leaderboard_id)
    reqrec = request.make_request()
    reqrec = reqrec.get("data")
    
    read_key_ver = reqrec.get("read").len()

    request = VerifyEntryRequest(entry_id, read_key_ver)
    request.safe_print(request.make_request())


def do_remove_entry(entry_id):
    request = RemoveEntryRequest(entry_id)
    request.safe_print(request.make_request())


def entry_options(entry_id):
    while True:
        print(
            "Entry Commands:\n"
            "[0] Go Back\n"
            "[1] View Entry\n"
            "[2] Add Proof\n"
            "[3] Download Proof\n"
            "[4] Remove Proof\n"
            "[5] View Comments\n"
            "[6] Post Comment\n"
            "[7] Verify Entry\n"
            "[8] Remove Entry\n")
        choice = input("Choose the corresponding number: ")
        if not choice.isdigit():
            print("Invalid input, please enter an integer")
            continue
        choice = int(choice)
        if choice == 0:
            break
        if choice == 1:
            do_get_entry(entry_id)
        elif choice == 2:
            do_add_proof(entry_id)
        elif choice == 3:
            do_get_proof()
        elif choice == 4:
            do_remove_proof()
        elif choice == 5:
            do_view_comments(entry_id)
        elif choice == 6:
            do_add_comment(entry_id)
        elif choice == 7:
            do_verify_entry(entry_id)
        elif choice == 8:
            do_remove_entry(entry_id)
            return
        else:
            print("Invalid choice. Please choose from the provided list.")


def do_show_leaderboards():
    request = ShowLeaderboardsRequest()
    request.safe_print(request.make_request())


def do_create_leaderboard():
    leaderboard_name = input("Enter the name for the new leaderboard: ")
    leaderboard_ascending = input("Score ascending [1] or descending [2]: ")
    if not leaderboard_ascending.isdigit() or int(leaderboard_ascending) > 2 \
            or int(leaderboard_ascending) < 1:
        print("Invalid input, please enter an integer listed")
        return
    leaderboard_ascending = int(leaderboard_ascending) == 1
    read_key = os.urandom(32)
    mod_sym_key = os.urandom(32)
    mod_priv_key = cryptolib.generate_rsa_key()
    mod_priv_key_bytes = netlib.serialize_private_key(mod_priv_key)
    encrypted_priv_key = cryptolib.symmetric_encrypt(mod_sym_key, mod_priv_key_bytes) 
    mod_encrypted_sym = cryptolib.rsa_encrypt(private_key.public_key(), mod_sym_key)
    encrypted_read_key = cryptolib.rsa_encrypt(private_key.public_key(), read_key)
    
    request = CreateLeaderboardRequest(leaderboard_name, leaderboard_ascending, 
                                       netlib.bytes_to_b64(netlib.serialize_public_key(mod_priv_key.public_key())),
                                       netlib.bytes_to_b64(encrypted_read_key),
                                       netlib.bytes_to_b64(mod_encrypted_sym),
                                       netlib.bytes_to_b64(encrypted_priv_key),
                                       )
    request.safe_print(request.make_request())


def do_list_users():
    request = ListUsersRequest()
    request.safe_print(request.make_request())


def do_one_leaderboard(leaderboard_id):
    request = OneLeaderboardRequest(leaderboard_id)
    request.safe_print(request.make_request())


def do_list_unverified(leaderboard_id):
    request = ListUnverifiedRequest(leaderboard_id)
    request.safe_print(request.make_request())


def do_add_entry(leaderboard_id):
    # TODO encrypt
    score = input("Enter your score: ")
    try:
        score = float(score)
    except ValueError:
        print("Must enter a number")
        return
    comment = input("Enter any comments about your score: ")

    sym_key = os.urandom(32)
    user_key = cryptolib.rsa_encrypt(private_key.public_key(), sym_key)
    score = cryptolib.symmetric_encrypt(sym_key, score)
    comment = cryptolib.symmetric_encrypt(sym_key, comment)

    request = GetSelfIDRequest()
    reqrec = request.make_request()
    user_id = reqrec.get("data")

    request = GetKeysRequest(user_id, leaderboard_id)
    reqrec = request.make_request()
    reqrec = reqrec.get("data")
    
    mod_key_ver = reqrec.get("mod").len()
    mod_group_pub_key = reqrec.get("mod_pub")

    mod_key = cryptolib.rsa_encrypt(mod_group_pub_key, sym_key)

    request = AddEntryRequest(leaderboard_id, score, comment, user_key, mod_key, mod_key_ver)
    request.safe_print(request.make_request())


def do_access_groups(leaderboard_id):
    request = AccessGroupsRequest(leaderboard_id)
    request.safe_print(request.make_request())


def do_set_score_order(leaderboard_id):
    ascending = input("Set to ascending [1] or descending [2]: ")
    if not ascending.isdigit() or int(ascending) > 2 \
            or int(ascending) < 1:
        print("Invalid input, please enter an integer listed")
        return
    ascending = int(ascending) == 1
    request = SetScoreOrderRequest(leaderboard_id, ascending)
    request.safe_print(request.make_request())


def do_remove_leaderboard(leaderboard_id):
    request = RemoveLeaderboardRequest(leaderboard_id)
    request.safe_print(request.make_request())


def do_get_self_id() -> Union[int, None]:
    request = GetSelfIDRequest()
    response = request.make_request()
    if "success" not in response or "data" not in response:
        print("Malformed packet: " + str(response))
        return None
    return int(response["data"])


def leaderboard_options(leaderboard_id):
    while True:
        print(
            "Leaderboard Commands:\n"
            "[0] Go Back\n"
            "[1] List Entries\n"
            "[2] Open Unverified\n"
            "[3] Submit Entry\n"
            "[4] Open Entry\n"
            "[5] View Access Groups\n"
            "[6] Set Score Order\n"
            "[7] Remove Leaderboard\n")
        choice = input("Choose the corresponding number: ")
        if not choice.isdigit():
            print("Invalid input, please enter an integer")
            continue
        choice = int(choice)
        if choice == 0:
            break
        elif choice == 1:
            do_one_leaderboard(leaderboard_id)
        elif choice == 2:
            do_list_unverified(leaderboard_id)
        elif choice == 3:
            do_add_entry(leaderboard_id)
        elif choice == 4:
            entry_id = input("Enter the ID of the entry: ")
            try:
                entry_id = int(entry_id)
            except ValueError:
                print("Invalid entry ID")
                continue
            entry_options(entry_id)
        elif choice == 5:
            do_access_groups(leaderboard_id)
        elif choice == 6:
            do_set_score_order(leaderboard_id)
        elif choice == 7:
            do_remove_leaderboard(leaderboard_id)
            return
        else:
            print("Invalid choice. Please choose from the provided list.")


def display():
    print("Authentication Server")
    print("{:<21.21}{:<16}{:<6}".format("Name", "IP", "Port"))
    auth_server = db["auth_server"]
    print("{:<21.21}{:<16}{:<6}".format(auth_server["name"], auth_server["ip"], auth_server["port"]))
    print("Resource Servers")
    print("{:<4}{:<21.21}{:<16}{:<6}".format("#", "Name", "IP", "Port"))
    server_count = 1
    for server in db["resource_servers"]:
        print("{:<4}{:<21.21}{:<16}{:<6}".format(server_count, server["name"], server["ip"], server["port"]))
        server_count += 1


def write_database_to_file():
    with open(db_filename, "w") as db_file:
        json.dump(db, db_file)


def initialize_database() -> dict:
    try:
        with open(db_filename, "r") as db_file:
            db_to_return = json.load(db_file)
            print("Successfully loaded database from file.")
    except json.decoder.JSONDecodeError:
        print("Could not read db from file. Exiting to avoid corrupting!")
    except FileNotFoundError:
        print("No database found! Initializing new database.")
        db_to_return = {
            "resource_servers": [],
        }
    return db_to_return


def main():
    if "auth_server" not in db:
        print("No authentication server found. Please add one now.")
        name = input("Name the server: ")[:20]
        ip = input("Enter the ip of the server: ")
        port = input("Enter the port of the server: ")
        db["auth_server"] = {"name": name, "ip": ip, "port": port, "key": ""}
        write_database_to_file()

    while True:
        display()
        print("\nChoices\n"
              "[C] connect to server\n"
              "[A] add server listing\n"
              "[E] edit server listing\n"
              "[R] remove server listing\n"
              "[Q] quit application")
        choice = input("Input letter of choice: ").lower()

        if choice == 'c':  # connect to resource server
            choice = input("Enter server number to connect to: ")
            if not choice.isdigit():
                print("Invalid input, please enter an integer")
                continue
            choice = int(choice) - 1
            try:
                server = db["resource_servers"][choice]
            except KeyError:
                print("Invalid server selection")
                continue
            server_loop(server["ip"], server["port"])
            sock.close()

        elif choice == 'a':  # add resource server to list
            name = input("Name the server: ")[:20]
            ip = input("Enter the ip of the server: ")
            port = input("Enter the port of the server: ")
            db["resource_servers"].append({"name": name, "ip": ip, "port": port, "key": ""})
            write_database_to_file()

        elif choice == 'e':  # edit resource server
            choice = input("Enter server number to edit (0 for auth. server): ")
            if not choice.isdigit():
                print("Invalid input, please enter an integer")
                continue
            choice = int(choice) - 1
            if choice == -1:
                server = db["auth_server"]
            else:
                try:
                    server = db["resource_servers"][choice]
                except KeyError:
                    print("Invalid server selection")
                    continue
            name = input("Enter new name (empty to leave as \"{}\"): ".format(server["name"]))[:20]
            if name != "":
                server["name"] = name
            ip = input("Enter new ip (empty to leave as \"{}\"): ".format(server["ip"]))
            if ip != "":
                server["ip"] = ip
            port = input("Enter new port (empty to leave as \"{}\"): ".format(server["port"]))
            if port != "":
                server["port"] = port
            write_database_to_file()

        elif choice == 'r':  # remove a resource server
            choice = input("Enter server number to remove: ")
            if not choice.isdigit():
                print("Invalid input, please enter an integer")
                continue
            choice = int(choice) - 1
            if choice == -1:
                print("Can't remove Authorization server, edit it instead")
                continue
            elif choice >= len(db["resource_servers"]) or choice < 0:
                print("Invalid server selection")
                continue
            db["resource_servers"].pop(choice)

        if choice == 'q':  # quit
            break


def server_loop(res_ip, res_port):
    global identity, token, sock, session_key

    # get AS pubkey
    auth_server = db["auth_server"]
    print("Trying to connect to {}:{}".format(auth_server["ip"], auth_server["port"]))
    try:
        sock = socket.socket()
        sock.connect((auth_server["ip"], int(auth_server["port"])))
    except OSError as e:
        print("Connection to authentication server failed! error: " + str(e))
        return
    print("Connection successful.")
    try:
        as_pub = request_pub_key()
    except BrokenPipeError:
        print("Authentication Server Closed Pipe")
        return
    if as_pub is None:
        print("No public key was found.")
        return
    if "as_pub" not in db["auth_server"]:
        db["auth_server"]["as_pub"] = netlib.bytes_to_b64(netlib.serialize_public_key(as_pub))
        write_database_to_file()
    sock.close()

    # get RS pubkey
    print("Trying to connect to {}:{}".format(res_ip, res_port))
    try:
        sock = socket.socket()
        sock.connect((res_ip, int(res_port)))
    except OSError as e:
        print("Connection to resource server failed! error: " + str(e))
        return
    print("Connection successful.")

    request = {
        "type": ResourceRequestType.PublicKey
    }
    netlib.send_dict_to_socket(request, sock)
    try:
        response = netlib.get_dict_from_socket(sock)
    except BrokenPipeError:
        print("Resource Server Broke Pipe")
        return
    if "success" in response and response["success"] and response["data"]:
        rs_pub_serialized = response["data"]
    else:
        print("RS public key request failed")
        return
    global rs_pub
    rs_pub = netlib.deserialize_public_key(rs_pub_serialized.encode())
    for rs in db["resource_servers"]:
        if rs["ip"] == res_ip and rs["port"] == res_port:
            if "rs_pub" in rs and rs["rs_pub"] != netlib.bytes_to_b64(netlib.serialize_public_key(rs_pub)):
                print("Requested public key doesn't match stored public key.")
                return
            elif "rs_pub" not in rs:
                while True:
                    print("No public key stored on file for {}:{}".format(res_ip, res_port))
                    print("Confirm New Key Hash: " + cryptolib.public_key_hash(rs_pub))
                    response = input("Does this look right? (y/n): ")
                    if response.lower() == "y":
                        rs["rs_pub"] = netlib.bytes_to_b64(netlib.serialize_public_key(rs_pub))
                        write_database_to_file()
                        print("New key saved to disk for {}:{}".format(res_ip, res_port))
                        break
                    elif response.lower() == "n":
                        print("Better to be safe than sorry!")
                        return
            else:
                print("Public key offered matches the one stored locally")
            break

    identity = input("Enter identity: ")
    password = input("Enter password: ")

    global key_filename
    global private_key
    key_filename = "client_" + identity + "_private_key"
    private_key = cryptolib.initialize_key(key_filename)

    # Get token
    print("Trying to connect to {}:{}".format(auth_server["ip"], auth_server["port"]))
    try:
        as_sock = socket.socket()
        as_sock.connect((auth_server["ip"], int(auth_server["port"])))
    except OSError as e:
        print("Connection to authentication server failed! error: " + str(e))
        return
    print("Connection successful.")
    try:
        data = request_token(as_sock, password, as_pub)
        if data is None:
            print("Login Failed!")
            return
        token = netlib.b64_to_bytes(data["token"])
        expiration_time = data["expiration_time"]
    except BrokenPipeError:
        print("Authentication Server Closed Pipe")
        return
    if token is None:
        print("Incorrect username or password!")
        return

    print("Login successful!")
    as_sock.close()

    aes_key = os.urandom(32)
    encrypted_key = cryptolib.rsa_encrypt(rs_pub, aes_key)
    public_key = private_key.public_key()
    public_key_bytes = netlib.serialize_public_key(public_key)
    signin_dict = {
        "identity": identity,
        "token": netlib.bytes_to_b64(token),
        "pubkey": netlib.bytes_to_b64(public_key_bytes),
        "expiration_time": expiration_time,
    }
    signin_payload = cryptolib.encrypt_dict(aes_key, signin_dict)

    # Authenticate with RS
    request = {
        "type": ResourceRequestType.Authenticate,
        "encrypted_key": netlib.bytes_to_b64(encrypted_key),
        "signin_payload": netlib.bytes_to_b64(signin_payload),
    }

    netlib.send_dict_to_socket(request, sock)
    try:
        response = netlib.get_dict_from_socket(sock)
    except BrokenPipeError:
        print("Resource Server Broke Pipe")
        return
    if response.get("nonce") is None:
        print("Password authentication failed!")
        return
    if response.get("signature") is None:
        print("Signature verification failed")
        return
    encrypted_nonce = netlib.b64_to_bytes(response["nonce"])
    signature = netlib.b64_to_bytes(response["signature"])
    if not cryptolib.rsa_verify(rs_pub, signature, encrypted_nonce):
        print("Signature verification failed")
        return
    nonce = cryptolib.symmetric_decrypt(aes_key, encrypted_nonce)
    nonce_plus_1 = netlib.int_to_bytes(netlib.bytes_to_int(nonce) + 1)
    encrypted_nonce = cryptolib.symmetric_encrypt(aes_key, nonce_plus_1)
    signature = cryptolib.rsa_sign(private_key, encrypted_nonce)
    base64_nonce = netlib.bytes_to_b64(encrypted_nonce)
    base64_signature = netlib.bytes_to_b64(signature)
    request = {
        "type": ResourceRequestType.NonceReply,
        "nonce": base64_nonce,
        "signature": base64_signature
    }
    netlib.send_dict_to_socket(request, sock)
    try:
        response = netlib.get_dict_from_socket(sock)
    except BrokenPipeError:
        print("Resource Server Broke Pipe")
        return
    if response is None or not response["success"]:
        print("Nonce authentication failed!")
        return

    print("Connected to " + res_ip + ":" + res_port + " as " + identity + "\n")
    session_key = aes_key

    global seqnum
    seqnum = 0

    # Resource server connection loop
    while True:
        print(
            "Basic Commands:\n"
            "[0] Quit\n"
            "[1] List Leaderboards\n"
            "[2] Open Leaderboard\n"
            "[3] Create Leaderboard\n"
            "[4] List Users\n"
            "[5] Open User\n"
            "[6] Open Self\n")
        choice = input("Choose the corresponding number: ")
        if not choice.isdigit():
            print("Invalid input, please enter an integer")
            continue
        choice = int(choice)
        try:
            if choice == 0:
                sock.close()
                break
            elif choice == 1:
                do_show_leaderboards()
            elif choice == 2:
                leaderboard_id = input("Enter the ID of the leaderboard: ")
                try:
                    leaderboard_id = int(leaderboard_id)
                except ValueError:
                    print("ID must be a number")
                    continue
                leaderboard_options(leaderboard_id)
            elif choice == 3:
                do_create_leaderboard()
            elif choice == 4:
                do_list_users()
            elif choice == 5:
                user_id = input("Enter the ID of the user: ")
                try:
                    user_id = int(user_id)
                except ValueError:
                    print("Invalid choice. Please choose from the provided list.")
                    continue
                user_options(user_id)
            elif choice == 6:
                user_options(do_get_self_id())
            else:
                print("Invalid choice. Please choose from the provided list.")
        except BrokenPipeError:
            print("Resource Server Closed Pipe")
            return

    sock.close()


if __name__ == "__main__":
    db_filename = "client_db"
    db = initialize_database()
    main()
