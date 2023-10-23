import json
import os
import struct
import socket
import base64
from datetime import datetime
from enums import ResourceRequestType, Permissions

identity: str = ""
token: str = ""
sock: socket.socket = socket.socket()

# formatting lookup tables
perms = ["No Access", "Read Access", "Write Access", "Mod", "Admin"]
bools = ["False", "True"]


def make_request(request: dict) -> dict:
    request = bytes(json.dumps(request), "utf-8")
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


# currently the only auth server request, so not using enum types
def request_token():
    return {
        "type": "token",
        "identity": identity,
    }


def request_show_leaderboards():
    return {
        "type": ResourceRequestType.ListLeaderboards,
        "identity": identity,
        "token": token,
    }


def request_create_leaderboard(leaderboard_name, leaderboard_permission, leaderboard_ascending):
    return {
        "type": ResourceRequestType.CreateLeaderboard,
        "identity": identity,
        "token": token,
        "leaderboard_name": leaderboard_name,
        "leaderboard_permission": leaderboard_permission,
        "leaderboard_ascending": leaderboard_ascending,
    }


def request_add_entry(leaderboard_id, score, comment):
    return {
        "type": ResourceRequestType.AddEntry,
        "identity": identity,
        "token": token,
        "leaderboard_id": leaderboard_id,
        "score": score,
        "comment": comment,
    }


def request_access_groups(leaderboard_id):
    return {
        "type": ResourceRequestType.ListAccessGroups,
        "identity": identity,
        "token": token,
        "leaderboard_id": leaderboard_id,
    }


def request_set_score_order(leaderboard_id, ascending):
    return {
        "type": ResourceRequestType.ChangeScoreOrder,
        "identity": identity,
        "token": token,
        "leaderboard_id": leaderboard_id,
        "ascending": ascending,
    }


def request_list_users():
    return {
        "type": ResourceRequestType.ListUsers,
        "identity": identity,
        "token": token,
    }


def request_list_unverified(leaderboard_id):
    return {
        "type": ResourceRequestType.ListUnverified,
        "identity": identity,
        "token": token,
        "leaderboard_id": leaderboard_id,
    }


def request_get_entry(entry_id):
    return {
        "type": ResourceRequestType.GetEntry,
        "identity": identity,
        "token": token,
        "entry_id": entry_id,
    }


def request_add_proof(entry_id, filename, blob):
    return {
        "type": ResourceRequestType.AddProof,
        "identity": identity,
        "token": token,
        "entry_id": entry_id,
        "filename": filename,
        "file": base64.b64encode(blob).decode(),
    }


def request_get_proof(file_id):
    return {
        "type": ResourceRequestType.DownloadProof,
        "identity": identity,
        "token": token,
        "file_id": file_id,
    }


def request_remove_proof(file_id):
    return {
        "type": ResourceRequestType.RemoveProof,
        "identity": identity,
        "token": token,
        "file_id": file_id,
    }


def request_view_user(user_id):
    return {
        "type": ResourceRequestType.ViewUser,
        "identity": identity,
        "token": token,
        "user_id": user_id,
    }


def request_one_leaderboard(leaderboard_id):
    return {
        "type": ResourceRequestType.ShowOneLeaderboard,
        "identity": identity,
        "token": token,
        "leaderboard_id": leaderboard_id,
    }


def request_view_permissions(user_id):
    return {
        "type": ResourceRequestType.ViewPermissions,
        "identity": identity,
        "token": token,
        "user_id": user_id,
    }


def request_modify_entry_verification(entry_id, verified):
    return {
        "type": ResourceRequestType.ModifyEntryVerification,
        "identity": identity,
        "token": token,
        "entry_id": entry_id,
        "verified": verified,
    }


def request_remove_leaderboard(leaderboard_id):
    return {
        "type": ResourceRequestType.RemoveLeaderboard,
        "identity": identity,
        "token": token,
        "leaderboard_id": leaderboard_id,
    }


def request_add_comment(entry_id, content):
    return {
        "type": ResourceRequestType.AddComment,
        "identity": identity,
        "token": token,
        "entry_id": entry_id,
        "content": content,
    }


def request_remove_entry(entry_id):
    return {
        "type": ResourceRequestType.RemoveEntry,
        "identity": identity,
        "token": token,
        "entry_id": entry_id,
    }


def request_set_permission(user_id, leaderboard_id, permission):
    return {
        "type": ResourceRequestType.SetPermission,
        "identity": identity,
        "token": token,
        "user_id": user_id,
        "permission": permission,
        "leaderboard_id": leaderboard_id,
    }


def request_remove_user(user_id):
    return {
        "type": ResourceRequestType.RemoveUser,
        "identity": identity,
        "token": token,
        "user_id": user_id,
    }


def request_get_id_from_identity():
    return {
        "type": ResourceRequestType.GetIdFromIdentity,
        "identity": identity,
        "token": token,
    }


def do_view_user(user_id):
    request = request_view_user(user_id)
    response = make_request(request)
    if "success" not in response or "data" not in response:
        print("Malformed packet: " + str(response))
        return
    if response["success"]:
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
    else:
        print(response["data"])


def do_view_permissions(user_id):
    request = request_view_permissions(user_id)
    response = make_request(request)
    if "success" not in response or "data" not in response:
        print("Malformed packet: " + str(response))
        return
    if response["success"]:
        print("{:<5}{:<12}".format("LB ID", "Permission"))
        for permission in response["data"]:
            print("{:<5}{:<12}".format(permission[0], perms[permission[1]]))
    else:
        print(response["data"])


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
    request = request_set_permission(user_id, leaderboard_id, permission)
    response = make_request(request)
    if "success" not in response or "data" not in response:
        print("Malformed packet: " + str(response))
        return
    if response["success"]:
        print("Operation successful.")
    else:
        print(response["data"])


def do_remove_user(user_id):
    request = request_remove_user(user_id)
    response = make_request(request)
    if "success" not in response or "data" not in response:
        print("Malformed packet: " + str(response))
        return
    if response["success"]:
        print("Operation Successful.")
    else:
        print(response["data"])


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


def do_get_entry(entry_id):
    request = request_get_entry(entry_id)
    response = make_request(request)
    if "success" not in response or "data" not in response:
        print("Malformed packet: " + str(response))
        return
    if response["success"]:
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

    else:
        print(response["data"])


def do_add_proof(entry_id):
    filename = input("Enter name of local file to upload: ")
    try:
        with open(filename, 'rb') as file:
            blob = file.read()
            request = request_add_proof(entry_id, filename, blob)
            response = make_request(request)
            if "success" not in response or "data" not in response:
                print("Malformed packet: " + str(response))
                return
            if response["success"]:
                print("Operation successful.")
            else:
                print(response["data"])
    except FileNotFoundError:
        print("File not found!")
    except IOError:
        print("IO error occurred!")


def do_get_proof(entry_id):
    remote_fileid = input("Enter id of remote file to download: ")
    if not remote_fileid.isdigit():
        print("Invalid input, please enter an integer")
        return
    remote_fileid = int(remote_fileid)
    local_filename = input("Enter name of local file to save it to: ")
    try:
        with open(local_filename, 'wb') as file:
            request = request_get_proof(remote_fileid)
            response = make_request(request)
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


def do_remove_proof(entry_id):
    remote_fileid = input("Enter id of remote file to remove: ")
    if not remote_fileid.isdigit():
        print("Invalid input, please enter an integer")
        return
    remote_fileid = int(remote_fileid)
    request = request_remove_proof(remote_fileid)
    response = make_request(request)
    if "success" not in response or "data" not in response:
        print("Malformed packet: " + str(response))
        return
    if response["success"]:
        print("Operation successful.")
    else:
        print(response["data"])


def do_view_comments(entry_id):
    request = request_get_entry(entry_id)
    response = make_request(request)
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
    request = request_add_comment(entry_id, content)
    response = make_request(request)
    if "success" not in response or "data" not in response:
        print("Malformed packet: " + str(response))
        return
    if response["success"]:
        print("Operation successful.")
    else:
        print(response["data"])


def do_modify_entry_verification(entry_id, verify):
    request = request_modify_entry_verification(entry_id, verify)
    response = make_request(request)
    if "success" not in response or "data" not in response:
        print("Malformed packet: " + str(response))
        return
    if response["success"]:
        print("Operation successful.")
    else:
        print(response["data"])


def do_remove_entry(entry_id):
    request = request_remove_entry(entry_id)
    response = make_request(request)
    if "success" not in response or "data" not in response:
        print("Malformed packet: " + str(response))
        return
    if response["success"]:
        print("Operation successful.")
    else:
        print(response["data"])


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
            do_get_proof(entry_id)
        elif choice == 4:
            do_remove_proof(entry_id)
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
        else:
            print("Invalid choice. Please choose from the provided list.")


def do_show_leaderboards():
    request = request_show_leaderboards()
    response = make_request(request)
    if "success" not in response or "data" not in response:
        print("Malformed packet: " + str(response))
        return
    if response["success"]:
        print("{:<4}{:<21.21}{:<6}".format("ID", "Leaderboard Name", "Permission"))
        for ldb in response["data"]:
            print("{:<4}{:<21.21}{:<6}".format(ldb[0], ldb[1], perms[ldb[2]]))
    else:
        print(response["data"])


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
    if not leaderboard_ascending.isdigit() or int(leaderboard_ascending) > 2\
            or int(leaderboard_ascending) < 1:
        print("Invalid input, please enter an integer listed")
        return
    leaderboard_ascending = int(leaderboard_ascending) == 1
    request = request_create_leaderboard(leaderboard_name, leaderboard_permission,
                                         leaderboard_ascending)
    response = make_request(request)
    if "success" not in response or "data" not in response:
        print("Malformed packet: " + str(response))
        return
    if response["success"]:
        print("New Leaderboard ID: {}".format(response["data"]))
    else:
        print(response["data"])


def do_list_users():
    request = request_list_users()
    response = make_request(request)
    if "success" not in response or "data" not in response:
        print("Malformed packet: " + str(response))
        return
    if response["success"]:
        print("{:<4}{:<21.21}".format("ID", "Username"))
        for user in response["data"]:
            print("{:<4}{:<21.21}".format(user[0], user[1]))
    else:
        print(response["data"])


def do_one_leaderboard(leaderboard_id):
    request = request_one_leaderboard(leaderboard_id)
    response = make_request(request)
    if "success" not in response or "data" not in response:
        print("Malformed packet: " + str(response))
        return
    if response["success"]:
        print("Leaderboard ID: {} Leaderboard Name: {}".format(response["data"]["id"], response["data"]["name"]))
        print("{:<9}{:<8}{:<21.21}{:<15}{:<20}{:<6}"
              .format("Entry ID", "User ID", "Username", "Score", "Date", "Verified"))
        for entry in response["data"]["entries"]:
            date = datetime.fromtimestamp(entry[4])
            print("{:<9}{:<8}{:<21.21}{:<15}{:<20}{:<6}"
                  .format(entry[0], entry[1], entry[2], entry[3], str(date), bools[entry[5]]))
    else:
        print(response["data"])


def do_list_unverified(leaderboard_id):
    request = request_list_unverified(leaderboard_id)
    response = make_request(request)
    if "success" not in response or "data" not in response:
        print("Malformed packet: " + str(response))
        return
    if response["success"]:
        print("{:<9}{:<8}{:<21.21}{:<15}{:<20}".format("Entry ID", "User ID", "Username", "Score", "Date"))
        for entry in response["data"]:
            date = datetime.fromtimestamp(entry[4])
            print("{:<9}{:<8}{:<21.21}{:<15}{:<20}".format(entry[0], entry[1], entry[2], entry[3], str(date)))
    else:
        print(response["data"])


def do_add_entry(leaderboard_id):
    score = input("Enter your score: ")
    try:
        score = float(score)
    except ValueError:
        print("Must enter a number")
        return
    comment = input("Enter any comments about your score: ")
    request = request_add_entry(leaderboard_id, score, comment)
    response = make_request(request)
    if "success" not in response or "data" not in response:
        print("Malformed packet: " + str(response))
        return
    if response["success"]:
        print("New Entry ID: {}".format(response["data"]))
    else:
        print(response["data"])


def do_access_groups(leaderboard_id):
    request = request_access_groups(leaderboard_id)
    response = make_request(request)
    if "success" not in response or "data" not in response:
        print("Malformed packet: " + str(response))
        return
    if response["success"]:
        print("{:<4}{:<21}{:<11}".format("ID", "Name", "Permission"))
        for user in response["data"]:
            print("{:<4}{:<21}{:<11}".format(user[0], user[1], user[2]))
    else:
        print(response["data"])


def do_set_score_order(leaderboard_id):
    ascending = input("Set to ascending [1] or descending [2]: ")
    if not ascending.isdigit() or int(ascending) > 2 \
            or int(ascending) < 1:
        print("Invalid input, please enter an integer listed")
        return
    ascending = int(ascending) == 1
    request = request_set_score_order(leaderboard_id, ascending)
    response = make_request(request)
    if "success" not in response or "data" not in response:
        print("Malformed packet: " + str(response))
        return
    if response["success"]:
        print("Operation successful.")
    else:
        print(response["data"])


def do_remove_leaderboard(leaderboard_id):
    request = request_remove_leaderboard(leaderboard_id)
    response = make_request(request)
    if "success" not in response or "data" not in response:
        print("Malformed packet: " + str(response))
        return
    if response["success"]:
        print("Operation successful.")
    else:
        print(response["data"])


def do_get_user_from_identity():
    request = request_get_id_from_identity()
    response = make_request(request)
    if "success" not in response or "data" not in response:
        print("Malformed packet: " + str(response))
        return
    return response["data"][0]


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
        else:
            print("Invalid choice. Please choose from the provided list.")


def clear_screen():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')


def display():
    clear_screen()

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
        db["auth_server"] = {"name": name, "ip": ip, "port": port}
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

        elif choice == 'a':  # add resource server to list
            name = input("Name the server: ")[:20]
            ip = input("Enter the ip of the server: ")
            port = input("Enter the port of the server: ")
            db["resource_servers"].append({"name": name, "ip": ip, "port": port})
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
    global identity, token, sock
    clear_screen()

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
    request = request_token()
    response = make_request(request)
    token = response["token"]
    sock.close()

    try:
        sock = socket.socket()
        sock.connect((res_ip, int(res_port)))
    except OSError as e:
        print("Connection to resource server failed! error: " + str(e))
        return
    print("Connected to " + res_ip + ":" + res_port + " as " + identity + "\n")
    while True:
        # clear_screen()
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
        elif choice == 5 or choice == 6:
            # 5: open user, 6: open self
            user_id = input("Enter the ID of the user: ") if choice == 5 else do_get_user_from_identity()
            try:
                user_id = int(user_id)
            except ValueError:
                print("Invalid user id")
                continue
            user_options(user_id)
        else:
            print("Invalid choice. Please choose from the provided list.")

    sock.close()


if __name__ == "__main__":
    db_filename = "client_db"
    db = initialize_database()
    main()
