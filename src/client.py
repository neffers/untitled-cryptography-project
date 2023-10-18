import json
import os
import asyncio
from enums import ResourceRequestType
# import time  # was used for sleeping before retrying connection

async def make_request(request: dict, reader, writer) -> dict:
    writer.write(bytes(json.dumps(request) + "\n", "utf-8"))
    await writer.drain()
    response_data = await reader.readline()
    response = json.loads(response_data.decode())
    return response

def request_token(identity):
    return {
        "type": "token",
        "identity": identity
    }

def request_show_leaderboards(identity, token):
    return {
        "type": ResourceRequestType.ListLeaderboards,
        "identity": identity,
        "token": token
    }

def request_create_leaderboard(identity, token, leaderboard_name, leaderboard_permission, leaderboard_ascending):
    return {
        "type": ResourceRequestType.CreateLeaderboard,
        "identity": identity,
        "token": token,
        "leaderboard_name": leaderboard_name,
        "leaderboard_permission": leaderboard_permission,
        "leaderboard_ascending": leaderboard_ascending
    }

def request_add_entry(identity, token, leaderboard_id, score, comment):
    return {
        "type": ResourceRequestType.AddEntry,
        "identity": identity,
        "token": token,
        "leaderboard_id": leaderboard_id,
        "score": score,
        "comment": comment
    }

def request_list_users(identity, token):
    return {
        "type": ResourceRequestType.ListUsers,
        "identity": identity,
        "token": token
    }

def request_list_unverified(identity, token, leaderboard_id):
    return {
        "type": ResourceRequestType.ListUnverified,
        "leaderboard_id": leaderboard_id,
        "identity": identity,
        "token": token
    }

def request_get_entry(identity, token, entry_id):
    return {
        "type": ResourceRequestType.GetEntry,
        "leaderboard_id": entry_id,
        "identity": identity,
        "token": token
    }

def request_view_user(identity, token, user_id):
    return {
        "type": ResourceRequestType.ViewUser,
        "leaderboard_id": user_id,
        "identity": identity,
        "token": token
    }

def request_one_leaderboard(identity, token, leaderboard_id):
    return {
        "type": ResourceRequestType.ShowOneLeaderboard,
        "leaderboard_id": leaderboard_id,
        "identity": identity,
        "token": token
    }

def request_view_permissions(identity, token):
    return {
        "type": ResourceRequestType.GetEntry,
        "identity": identity,
        "token": token
    }

def request_modify_entry_verification(identity, token, entry_id, verified):
    return {
        "type": ResourceRequestType.GetEntry,
        "leaderboard_id": entry_id,
        "identity": identity,
        "token": token,
        "verified": verified
    }

def request_remove_leaderboard(identity, token, leaderboard_id):
    return {
        "type": ResourceRequestType.RemoveLeaderboard,
        "leaderboard_id": leaderboard_id,
        "identity": identity,
        "token": token
    }

def request_add_comment(identity, token, entry_id, content):
    return {
        "type": ResourceRequestType.RemoveLeaderboard,
        "entry_id": entry_id,
        "content": content,
        "identity": identity,
        "token": token
    }

def request_remove_entry(identity, token, entry_id):
    return {
        "type": ResourceRequestType.RemoveLeaderboard,
        "entry_id": entry_id,
        "identity": identity,
        "token": token
    }

def request_set_permission(identity,token, user_id, leaderboard_id, permission):
    return {
        "type": ResourceRequestType.RemoveLeaderboard,
        "user_id": user_id,
        "permission": permission,
        "identity": identity,
        "token": token,
        "leaderboard_id": leaderboard_id
    }

def do_view_user(identity, token, reader, writer, user_id):
    request = request_view_user(identity, token, user_id)
    response = asyncio.run_until_complete(make_request(request, reader, writer))
    if response["success"] == True:
        print(response["data"])
    else:
        print(response["success"])

def do_view_permissions(identity, token, reader, writer, user_id):
    request = request_view_permissions(identity, token, user_id)
    response = asyncio.run_until_complete(make_request(request, reader, writer))
    if response["success"] == True:
        print(response["data"])
    else:
        print(response["success"])

def do_set_permission(identity, token, reader, writer, user_id):
    leaderboard_id = input("Enter the leaderboard where the permission will be changed: ")
    permission = input("What is the new permission level for the user?\nPlease enter 'none', 'read', 'write', or 'moderator': ")
    request = request_set_permission(identity, token, leaderboard_id, user_id, permission)
    response = asyncio.run_until_complete(make_request(request, reader, writer))
    if response["success"] == True:
        pass
    else:
        print(response["success"])

def user_options(identity, token, reader, writer, user_id):
    print("User Commands:\n[1] View User\n[2] View Permissions\n[3] Set Permissions\n[4] Open Submission\n[5] Remove User\n")
    choose4 = input("Choose the corresponding number: ")
    choose4 = int(choose4)
    if choose4 == 1:
        # view user
        do_view_user(identity, token, reader, writer, user_id)
    if choose4 == 2:
        # view permissions
        do_view_permissions(identity, token, reader, writer, user_id)
    if choose4 == 3:
        # set permissions
        do_set_permission(identity, token, reader, writer, user_id)
    if choose4 == 4:
        # open submission
        entry_id = input("Enter the ID of the entry: ")
        entry_options(identity, token, reader, writer, entry_id)
    if choose4 == 5:
        # remove user
        pass

def do_get_entry(identity, token, reader, writer, entry_id):
    request = request_get_entry(identity, token, entry_id)
    response = asyncio.run_until_complete(make_request(request, reader, writer))
    if response["success"] == True:
        print(response["data"])
    else:
        print(response["success"])

def do_view_comments(identity, token, reader, writer, entry_id):
    request = request_get_entry(identity, token, entry_id)
    response = asyncio.run_until_complete(make_request(request, reader, writer))
    if response["success"] == True:
        print(response["data"])
    else:
        print(response["success"])

def do_add_comment(identity, token, reader, writer, entry_id):
    content = input("Enter your comment to the entry: ")
    request = request_add_comment(identity, token, entry_id, content)
    response = asyncio.run_until_complete(make_request(request, reader, writer))
    if response["success"] == True:
        pass
    else:
        print(response["success"])

def do_modify_entry_verification(identity, token, reader, writer, entry_id, boolean):
    request = request_modify_entry_verification(identity, token, entry_id, boolean)
    response = asyncio.run_until_complete(make_request(request, reader, writer))
    if response["success"] == True:
        pass
    else:
        print(response["success"])

def do_remove_entry(identity, token, reader, writer, entry_id):
    request = request_remove_entry(identity, token, entry_id)
    response = asyncio.run_until_complete(make_request(request, reader, writer))
    if response["success"] == True:
        pass
    else:
        print(response["success"])

def entry_options(identity, token, reader, writer, entry_id):
    # begin entry options
    print("Leaderboard Commands:\n[1] View Entry\n[2] Add Proof\n[3] Download Proof\n[4] View Comments\n[5] Post Comment\n[6] Verify Entry\n[7] Unverify Entry\n[8] Remove Entry\n")
    choose3 = input("Choose the corresponding number: ")
    choose3 = int(choose3)
    if choose3 == 1:
        # view entry
        do_get_entry(identity, token, reader, writer, entry_id)
    if choose3 == 2:
        # add proof
        pass
    if choose3 == 3:
        # download proof
        pass
    if choose3 == 4:
        # view comments
        do_view_comments(identity, token, reader, writer, entry_id)
    if choose3 == 5:
        # post comment
        do_add_comment(identity, token, reader, writer, entry_id)
    if choose3 == 6:
        # verify entry
        do_modify_entry_verification(identity, token, reader, writer, entry_id, True)
    if choose3 == 7:
        # unverify entry
        do_modify_entry_verification(identity, token, reader, writer, entry_id, False)
    if choose3 == 8:
        # remove entry
        do_remove_entry(identity, token, reader, writer, entry_id)

def do_show_leaderboards(identity, token, reader, writer):
    request = request_show_leaderboards(identity, token)
    response = asyncio.run_until_complete(make_request(request, reader, writer))
    if response["success"] == True:
        print(response["data"])
    else:
        print(response["success"])

def do_create_leaderboard(identity, token, reader, writer):
    leaderboard_name = input("Enter the name for the new leaderboard: ")
    leaderboard_permission = input("What is the default permission level for users?\nPlease enter 'none', 'read', 'write', or 'moderator': ")
    leaderboard_ascending = input("Do you want your leaderboard to score ascending [1] or descending [2] ? ")
    if leaderboard_ascending == 1:
        leaderboard_ascending = True
    else:
        leaderboard_ascending = False
    request = request_create_leaderboard(identity, token, leaderboard_name, leaderboard_permission, leaderboard_ascending)
    response = asyncio.run_until_complete(make_request(request, reader, writer))
    if response["success"] == True:
        print("Leaderboard successfully created. Leaderboard ID is "+response["data"])
    else:
        print(response["success"])

def do_list_users(identity, token, reader, writer):
    request = request_list_users(identity, token)
    response = asyncio.run_until_complete(make_request(request, reader, writer))
    if response["success"] == True:
        print(response["data"])
    else:
        print(response["success"])

def do_one_leaderboard(identity, token, reader, writer, leaderboard_id):
    request = request_one_leaderboard(identity, token, leaderboard_id)
    response = asyncio.run_until_complete(make_request(request, reader, writer))
    if response["success"] == True:
        print(response["data"])
    else:
        print(response["success"])

def do_list_unverified(identity, token, reader, writer, leaderboard_id):
    request = request_list_unverified(identity, token, leaderboard_id)
    response = asyncio.run_until_complete(make_request(request, reader, writer))
    if response["success"] == True:
        print(response["data"])
    else:
        print(response["success"])

def do_add_entry(identity, token, reader, writer, leaderboard_id):
    score = input("Enter your score: ")
    score = float(score)
    comment = input("Enter any comments about your score: ")
    request = request_add_entry(identity, token, leaderboard_id, score, comment)
    response = asyncio.run_until_complete(make_request(request, reader, writer))
    if response["success"] == True:
        print("Entry successfully submitted. Entry ID is "+response["data"])
    else:
        print(response["success"])

def do_remove_leaderboard(identity, token, reader, writer, leaderboard_id):
    request = request_remove_leaderboard(identity, token, leaderboard_id)
    response = asyncio.run_until_complete(make_request(request, reader, writer))
    if response["success"] == True:
        pass
    else:
        print(response["success"])

def leaderboard_options(identity, token, reader, writer):
    leaderboard_id = input("Enter the leaderboard ID: ")
    leaderboard_id = int(leaderboard_id)
    # begin list options
    print("Leaderboard Commands:\n[1] List Entries\n[2] Open Unverified\n[3] Submit Entry\n[4] Open Entry\n[5] Score Order\n[6] Remove Leaderboard\n")
    choose2 = input("Choose the corresponding number: ")
    choose2 = int(choose2)
    if choose2 == 1:
        # list entries
        do_one_leaderboard(identity, token, reader, writer, leaderboard_id)
    if choose2 == 2:
        # open unverified
        do_list_unverified(identity, token, reader, writer, leaderboard_id)
    if choose2 == 3:
        # submit entry
        do_add_entry(identity, token, reader, writer, leaderboard_id)
    if choose2 == 4:
        # open entry
        entry_id = input("Enter the ID of the entry: ")
        entry_options(identity, token, reader, writer, entry_id)
    if choose2 == 5:
        # score order
        pass
    if choose2 == 6:
        # remove leaderboard
        do_remove_leaderboard(identity, token, reader, writer, leaderboard_id)


def clear_screen():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')


def display():
    clear_screen()

    print("Authentication Server")
    print("{:<21}{:<16}{:<6}".format("Name:", "IP:", "Port:"))
    auth_server = db["auth_server"]
    print("{:<21}{:<16}{:<6}".format(auth_server["name"], auth_server["ip"], auth_server["port"]))
    print("Resource Servers")
    print("{:<4}{:<21}{:<16}{:<6}".format("#", "Name:", "IP:", "Port:"))
    server_count = 1
    for server in db["resource_servers"]:
        print("{:<4}{:<21}{:<16}{:<6}".format(server_count, server["name"], server["ip"], server["port"]))
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
            choice = int(input("Enter server number to connect to: ")) - 1
            try:
                server = db["resource_servers"][choice]
            except KeyError:
                print("Invalid server selection")
                continue
            asyncio.run(server_loop(server["ip"], server["port"]))

        elif choice == 'a':  # add resource server to list
            name = input("Name the server: ")[:20]
            ip = input("Enter the ip of the server: ")
            port = input("Enter the port of the server: ")
            db["resource_servers"].append({"name": name, "ip": ip, "port": port})
            write_database_to_file()

        elif choice == 'e':  # edit resource server
            choice = int(input("Enter server number to edit (0 for auth. server): ")) - 1
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
            choice = int(input("Enter server number to remove: ")) - 1
            # this ensures there is a server there but there is likely a faster way
            try:
                server = db["resource_servers"][choice]
            except KeyError:
                print("Invalid server selection")
                continue
            db["resource_servers"].pop(choice)

        if choice == 'q':  # quit
            break


async def server_loop(res_ip, res_port):
    clear_screen()

    auth_server = db["auth_server"]
    print("Trying to connect to {}:{}".format(auth_server["ip"], auth_server["port"]))
    reader, writer = await asyncio.open_connection(auth_server["ip"], int(auth_server["port"]))
    # TODO handle failed connection
    print("Connection successful.")
    identity = input("Enter identity: ")
    request = request_token(identity)
    writer.write(bytes(json.dumps(request) + "\n", "utf-8"))
    await writer.drain()
    response_data = await reader.read()
    response = json.loads(response_data.decode())
    # TODO handle bad packets or error packets
    token = response["token"]

    reader, writer = await asyncio.open_connection(res_ip, int(res_port))
    # TODO handle failed connection
    while True:
        #clear_screen()
        print("Current Server: "+res_ip+":"+res_port)
        print("Current User: "+identity+"\n")
        print("Basic Commands:\n[1] List Leaderboards\n[2] Open Leaderboard\n[3] Create Leaderboard\n[4] List Users\n[5] Open User\n[6] Open Self\n[7] Quit\n")
        choose = input("Choose the corresponding number: ")
        choose = int(choose)
        if choose == 1:
            # list leaderboards
            do_show_leaderboards(identity, token, reader, writer)
        if choose == 2:
            # open leaderboard
            leaderboard_options(identity, token, reader, writer)
        if choose == 3:
            # create leaderboard
            do_create_leaderboard(identity, token, reader, writer)
        if choose == 4:
            # list users
            do_list_users(identity, token, reader, writer)
        if choose == 5 or choose == 6:
            # open user
            if choose == 5:
                user_id = input("Enter the ID of the user: ")
            # open self
            if choose == 6:
                user_id = identity
            user_options(identity, token, reader, writer, user_id)
        if choose == 7:
            # quit
            break

    writer.close()
    await writer.wait_closed()


if __name__ == "__main__":
    db_filename = "client_db"
    db = initialize_database()
    main()
