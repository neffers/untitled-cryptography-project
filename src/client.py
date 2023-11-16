import json
import struct
import socket
import base64
from datetime import datetime
from typing import Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import os
import netlib
import cryptolib
from enums import AuthRequestType, ResourceRequestType, Permissions

identity: str = ""
token: str = ""
sock: socket.socket = socket.socket()

# formatting lookup tables
perms = ["No Access", "Read Access", "Write Access", "Mod", "Admin"]
bools = ["False", "True"]


class Request:
    def __init__(self, request: dict):
        self.request = request

    def make_request(self) -> dict:
        request = self.request
        request["identity"] = identity
        request["token"] = netlib.bytes_to_b64(token)
        request = bytes(json.dumps(self.request), "utf-8")
        buffer = struct.pack("!I", len(request))
        buffer += request
        sock.send(buffer)
        buffer_len = struct.unpack("!I", sock.recv(4))[0]
        response_data = sock.recv(buffer_len)
        try:
            response = json.loads(response_data.decode())
            return response
        except json.JSONDecodeError:
            print("Can't decode packet! packet: " + str(response_data))
            return dict()

    def safe_print(self, response: dict) -> None:
        if "success" not in response or "data" not in response:
            print("Malformed packet: " + str(response))
            return
        if response["success"]:
            self.print_response(response)
        else:
            print(response["data"])

    def print_response(self, response):
        print("Operation successful.")


# Auth server request
def request_token(password, as_pub) -> Union[bytes, None]:
    aes_key = os.urandom(32)
    encrypted_key = cryptolib.rsa_encrypt(as_pub, aes_key)
    signin_dict = {
        "identity": identity,
        "password": password,
    }
    signin_payload = cryptolib.encrypt_dict(aes_key, signin_dict)
    request = {
        "type": AuthRequestType.Token,
        "encrypted_key": netlib.bytes_to_b64(encrypted_key),
        "signin_payload": netlib.bytes_to_b64(signin_payload),
    }
    netlib.send_dict_to_socket(request, sock)
    response = netlib.get_dict_from_socket(sock)
    if "success" in response:
        if response["success"]:
            return cryptolib.symmetric_decrypt(aes_key, netlib.b64_to_bytes(response["data"]))

    return None


# Auth server request
def request_pub_key() -> Union[rsa.RSAPublicKey, None]:
    request = {
        "type": AuthRequestType.PublicKey,
    }
    netlib.send_dict_to_socket(request, sock)
    response = netlib.get_dict_from_socket(sock)
    if "success" in response and response["success"]:
        return serialization.load_ssh_public_key(response["data"].encode())

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
    def __init__(self, leaderboard_name, leaderboard_permission, leaderboard_ascending):
        super().__init__({
            "type": ResourceRequestType.CreateLeaderboard,
            "leaderboard_name": leaderboard_name,
            "leaderboard_permission": leaderboard_permission,
            "leaderboard_ascending": leaderboard_ascending,
        })

    def print_response(self, response):
        print("New Leaderboard ID: {}".format(response["data"]))


class AddEntryRequest(Request):
    def __init__(self, leaderboard_id, score, comment):
        super().__init__({
            "type": ResourceRequestType.AddEntry,
            "leaderboard_id": leaderboard_id,
            "score": score,
            "comment": comment,
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
        print("{:<9}{:<8}{:<21.21}{:<15}{:<20}".format("Entry ID", "User ID", "Username", "Score", "Date"))
        for entry in response["data"]:
            date = datetime.fromtimestamp(entry[4])
            print("{:<9}{:<8}{:<21.21}{:<15}{:<20}".format(entry[0], entry[1], entry[2], entry[3], str(date)))


class GetEntryRequest(Request):
    def __init__(self, entry_id):
        super().__init__({
            "type": ResourceRequestType.GetEntry,
            "entry_id": entry_id
        })

    def print_response(self, response):
        entry = response["data"]["entry"]
        print("{:<9}{:<8}{:<21.21}{:<15}{:<20}{:<9}{:<7}{:<21.21}"
              .format("Entry ID", "User ID", "Username", "Score", "Date", "Verified", "Mod ID", "Mod Name"))
        date = datetime.fromtimestamp(entry[4])
        mod_id = entry[6] if entry[6] else "N/A"
        mod_name = entry[7] if entry[7] else "N/A"
        print("{:<9}{:<8}{:<21.21}{:<15}{:<20}{:<9}{:<7}{:<21.21}"
              .format(entry[0], entry[1], entry[2], entry[3], str(date), bools[entry[5]], mod_id, mod_name))
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
    def __init__(self, entry_id, filename, blob):
        super().__init__({
            "type": ResourceRequestType.AddProof,
            "entry_id": entry_id,
            "filename": filename,
            "file": base64.b64encode(blob).decode()
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
        print("{:<4}{:<5}{:<15}{:<9}{:<20}"
              .format("ID", "LB ID", "Score", "Verified", "Registration Date"))
        for entry in entries:
            date = datetime.fromtimestamp(entry[4])
            print("{:<4}{:<5}{:<15}{:<9}{:<20}"
                  .format(entry[0], entry[1], entry[2], bools[entry[3]], str(date)))


class OneLeaderboardRequest(Request):
    def __init__(self, leaderboard_id):
        super().__init__({
            "type": ResourceRequestType.ShowOneLeaderboard,
            "leaderboard_id": leaderboard_id
        })

    def print_response(self, response):
        print("Leaderboard ID: {} Leaderboard Name: {}".format(response["data"]["id"], response["data"]["name"]))
        print("{:<9}{:<8}{:<21.21}{:<15}{:<20}{:<6}"
              .format("Entry ID", "User ID", "Username", "Score", "Date", "Verified"))
        for entry in response["data"]["entries"]:
            date = datetime.fromtimestamp(entry[4])
            print("{:<9}{:<8}{:<21.21}{:<15}{:<20}{:<6}"
                  .format(entry[0], entry[1], entry[2], entry[3], str(date), bools[entry[5]]))


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


class ModifyEntryVerificationRequest(Request):
    def __init__(self, entry_id, verified):
        super().__init__({
            "type": ResourceRequestType.ModifyEntryVerification,
            "entry_id": entry_id,
            "verified": verified
        })


class RemoveLeaderboardRequest(Request):
    def __init__(self, leaderboard_id):
        super().__init__({
            "type": ResourceRequestType.RemoveLeaderboard,
            "leaderboard_id": leaderboard_id
        })


class AddCommentRequest(Request):
    def __init__(self, entry_id, content):
        super().__init__({
            "type": ResourceRequestType.AddComment,
            "entry_id": entry_id,
            "content": content
        })


class RemoveEntryRequest(Request):
    def __init__(self, entry_id):
        super().__init__({
            "type": ResourceRequestType.RemoveEntry,
            "entry_id": entry_id
        })


class SetPermissionRequest(Request):
    def __init__(self, user_id, leaderboard_id, permission):
        super().__init__({
            "type": ResourceRequestType.SetPermission,
            "user_id": user_id,
            "leaderboard_id": leaderboard_id,
            "permission": permission
        })


class RemoveUserRequest(Request):
    def __init__(self, user_id):
        super().__init__({
            "type": ResourceRequestType.RemoveUser,
            "user_id": user_id
        })


class GetSelfID(Request):
    def __init__(self):
        super().__init__({
            "type": ResourceRequestType.GetSelfID,
            "user_id": identity
        })


def do_view_user(user_id):
    request = ViewUserRequest(user_id)
    request.safe_print(request.make_request())


def do_view_permissions(user_id):
    request = ViewPermissionsRequest(user_id)
    request.safe_print(request.make_request())


def do_set_permission(user_id):
    leaderboard_id = input("Enter the leaderboard id where the permission will be changed: ")
    if not leaderboard_id.isdigit():
        print("Invalid input, please enter an integer")
        return
    leaderboard_id = int(leaderboard_id)
    permission = input(
        "[0] None\n"
        "[1] Read\n"
        "[2] Write\n"
        "[3] Moderator\n"
        "Select new permission level: ")
    if not permission.isdigit() or int(permission) > 3:
        print("Invalid input, please enter an integer listed above")
        return
    permission = int(permission)
    if permission == 0:
        permission = Permissions.NoAccess
    elif permission == 1:
        permission = Permissions.Read
    elif permission == 2:
        permission = Permissions.Write
    elif permission == 3:
        permission = Permissions.Moderate
    request = SetPermissionRequest(user_id, leaderboard_id, permission)
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
            "[3] Set Permissions\n"
            "[4] Open Submission\n"
            "[5] Remove User\n")
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
            do_set_permission(user_id)
        elif choice == 4:
            entry_id = input("Enter the ID of the entry: ")
            try:
                entry_id = int(entry_id)
            except ValueError:
                print("Invalid entry ID")
                continue
            entry_options(entry_id)
        elif choice == 5:
            do_remove_user(user_id)
            return


def do_get_entry(entry_id):
    request = GetEntryRequest(entry_id)
    request.safe_print(request.make_request())


def do_add_proof(entry_id):
    filename = input("Enter name of local file to upload: ")
    try:
        with open(filename, 'rb') as file:
            blob = file.read()
            request = AddProofRequest(entry_id, filename, blob)
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
                data = response["data"]
                file.write(base64.b64decode(data))
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
        print("{:<21.21}{:<20}{}".format("Commenter", "Date", "Comment"))
        for comment in comments:
            date = datetime.fromtimestamp(comment[1])
            print("{:<21.21}{:<20}{}".format(comment[0], str(date), comment[2]))
    else:
        print(response["data"])


def do_add_comment(entry_id):
    content = input("Enter your comment to the entry: ")
    request = AddCommentRequest(entry_id, content)
    request.safe_print(request.make_request())


def do_modify_entry_verification(entry_id, verify):
    request = ModifyEntryVerificationRequest(entry_id, verify)
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
            "[8] Un-verify Entry\n"
            "[9] Remove Entry\n")
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
            do_modify_entry_verification(entry_id, True)
        elif choice == 8:
            do_modify_entry_verification(entry_id, False)
        elif choice == 9:
            do_remove_entry(entry_id)
            return
        else:
            print("Invalid choice. Please choose from the provided list.")


def do_show_leaderboards():
    request = ShowLeaderboardsRequest()
    request.safe_print(request.make_request())


def do_create_leaderboard():
    leaderboard_name = input("Enter the name for the new leaderboard: ")
    leaderboard_permission = input(
        "[0] None\n"
        "[1] Read\n"
        "[2] Write\n"
        "[3] Moderator\n"
        "Enter default permissions for leaderboard: ")
    if not leaderboard_permission.isdigit() or int(leaderboard_permission) > 3:
        print("Invalid input, please enter an integer listed above")
        return
    leaderboard_permission = int(leaderboard_permission)
    if leaderboard_permission == 0:
        leaderboard_permission = Permissions.NoAccess
    elif leaderboard_permission == 1:
        leaderboard_permission = Permissions.Read
    elif leaderboard_permission == 2:
        leaderboard_permission = Permissions.Write
    elif leaderboard_permission == 3:
        leaderboard_permission = Permissions.Moderate
    leaderboard_ascending = input("Score ascending [1] or descending [2]: ")
    if not leaderboard_ascending.isdigit() or int(leaderboard_ascending) > 2 \
            or int(leaderboard_ascending) < 1:
        print("Invalid input, please enter an integer listed")
        return
    leaderboard_ascending = int(leaderboard_ascending) == 1
    request = CreateLeaderboardRequest(leaderboard_name, leaderboard_permission,
                                       leaderboard_ascending)
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
    score = input("Enter your score: ")
    try:
        score = float(score)
    except ValueError:
        print("Must enter a number")
        return
    comment = input("Enter any comments about your score: ")
    request = AddEntryRequest(leaderboard_id, score, comment)
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
    request = GetSelfID()
    response = request.make_request()
    if "success" not in response or "data" not in response:
        print("Malformed packet: " + str(response))
        return None
    return int(response["data"][0])


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


def write_database_to_file(database, db_filename):
    with open(db_filename, "w") as db_file:
        json.dump(database, db_file)


def initialize_database(db_filename) -> dict:
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
        write_database_to_file(db, "client_db")

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

        elif choice == 'a':  # add resource server to list
            name = input("Name the server: ")[:20]
            ip = input("Enter the ip of the server: ")
            port = input("Enter the port of the server: ")
            db["resource_servers"].append({"name": name, "ip": ip, "port": port, "key": ""})
            write_database_to_file(db, "client_db")

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
            write_database_to_file(db, "client_db")

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
    global identity, token, sock

    # Authentication process
    auth_server = db["auth_server"]
    print("Trying to connect to {}:{}".format(auth_server["ip"], auth_server["port"]))
    try:
        sock = socket.socket()
        sock.connect((auth_server["ip"], int(auth_server["port"])))
    except OSError as e:
        print("Connection to authentication server failed! error: " + str(e))
        return
    print("Connection successful.")

    as_pub = request_pub_key()
    if as_pub is None:
        print("No public key was found.")
        return
    if "as_pub" in db["auth_server"]:
        if db["auth_server"]["as_pub"] != netlib.bytes_to_b64(as_pub.public_bytes(encoding=serialization.Encoding.PEM,
                                                                                  format=serialization.PublicFormat.SubjectPublicKeyInfo)):
            print("Requested public key doesn't match stored public key.")
            return
    else:
        db["auth_server"]["as_pub"] = netlib.bytes_to_b64(as_pub.public_bytes(encoding=serialization.Encoding.PEM,
                                                                              format=serialization.PublicFormat.SubjectPublicKeyInfo))
    print("AS public key checks out")
    sock.close()

    auth_server = db["auth_server"]
    print("Trying to connect to {}:{}".format(auth_server["ip"], auth_server["port"]))
    try:
        sock = socket.socket()
        sock.connect((auth_server["ip"], int(auth_server["port"])))
    except OSError as e:
        print("Connection to authentication server failed! error: " + str(e))
        return
    print("Connection successful.")
    identity = input("Enter identity: ")
    password = input("Enter password: ")
    token = request_token(password, as_pub)
    if token is None:
        print("Incorrect username or password!")
        sock.close()
        return

    print("Login successful!")
    sock.close()

    # Resource server handshake
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
    response = netlib.get_dict_from_socket(sock)
    if "success" in response and response["success"] and response["data"]:
        rs_pub_serialized = response["data"]
    else:
        print("RS public key request failed")
        return
    rs_pub: rsa.RSAPublicKey = serialization.load_ssh_public_key(rs_pub_serialized.encode())
    for rs in db["resource_servers"]:
        if rs["ip"] == res_ip and rs["port"] == res_port:
            if "rs_pub" in rs and rs["rs_pub"] != netlib.bytes_to_b64(
                    rs_pub.public_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PublicFormat.SubjectPublicKeyInfo)):
                print("Requested public key doesn't match stored public key.")
                return
            elif "rs_pub" not in rs:
                while True:
                    print("No public key stored on file for {}:{}".format(res_ip, res_port))
                    print("Confirm New Key Hash: " + cryptolib.public_key_hash(rs_pub))
                    response = input("Does this look right? (y/n): ")
                    if response.lower() == "y":
                        rs["rs_pub"] = netlib.bytes_to_b64(rs_pub.public_bytes(encoding=serialization.Encoding.PEM,
                                                                               format=serialization.PublicFormat.SubjectPublicKeyInfo))
                        print("New key saved to disk for {}:{}".format(res_ip, res_port))
                        break
                    elif response.lower() == "n":
                        print("Better to be safe than sorry!")
                        return
            else:
                print("Public key offered matches the one stored locally")
            break

    aes_key = os.urandom(32)
    encrypted_key = cryptolib.rsa_encrypt(rs_pub, aes_key)
    signin_dict = {
        "identity": identity,
        "token": netlib.bytes_to_b64(token),
    }
    signin_payload = cryptolib.encrypt_dict(aes_key, signin_dict)
    request = {
        "type": ResourceRequestType.Authenticate,
        "encrypted_key": netlib.bytes_to_b64(encrypted_key),
        "signin_payload": netlib.bytes_to_b64(signin_payload),
    }

    print("Attempting login...")
    netlib.send_dict_to_socket(request, sock)
    response = netlib.get_dict_from_socket(sock)
    # TODO error handling if you dont get a nonce back or something
    encrypted_nonce = response["nonce"]
    nonce = cryptolib.symmetric_decrypt(aes_key, netlib.b64_to_bytes(encrypted_nonce))
    nonce_plus_1 = netlib.int_to_bytes(netlib.bytes_to_int(nonce) + 1)
    request = {
        "type": ResourceRequestType.NonceReply,
        "nonce": netlib.bytes_to_b64(cryptolib.symmetric_encrypt(aes_key, nonce_plus_1)),
    }
    netlib.send_dict_to_socket(request, sock)
    response = netlib.get_dict_from_socket(sock)
    if response is None or not response["success"]:
        print("Nonce authentication failed!")
        return

    print("Connected to " + res_ip + ":" + res_port + " as " + identity + "\n")

    # Resource server connection loop
    while True:
        print(
            "Basic Commands:\n"
            "[0] Quit\n"
            "[1] List Leaderboards\n"
            "[2] Open Leaderboard\n"
            "[3] Create Leaderboard\n"
            "[4] List Users\n"
            "[5] Open Self\n")
        choice = input("Choose the corresponding number: ")
        if not choice.isdigit():
            print("Invalid input, please enter an integer")
            continue
        choice = int(choice)
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
            user_options(do_get_self_id())
        else:
            print("Invalid choice. Please choose from the provided list.")

    sock.close()


if __name__ == "__main__":
    db = initialize_database("client_db")
    main()
