import json
import os
import asyncio
from enums import ResourceRequestType
# import time  # was used for sleeping before retrying connection

def request_token(identity):
    return {
        "type": "token",
        "identity": identity
    }


def request_show_leaderboards(identity, token):
    return {
        "type": ResourceRequestType.ShowLeaderboards,
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


def clear_screen():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')

def display():
    clear_screen()

    print("Authentication Server")
    print("{:<21}{:<12}{:<6}".format("Name:", "IP:", "Port:"))
    auth_server = db["auth_server"]
    print("{:<21}{:<12}{:<6}".format(auth_server["name"], auth_server["ip"], auth_server["port"]))
    print("Resource Servers")
    print("{:<4}{:<21}{:<12}{:<6}".format("#", "Name:", "IP:", "Port:"))
    server_count = 1
    for server in db["resource_servers"]:
        print("{:<4}{:<21}{:<12}{:<6}".format(server_count, server["name"], server["ip"], server["port"]))
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
            choice = int(input("Enter server number to edit (0 for auth. server): "))
            if choice == 0:
                server = db["auth_server"]
            else:
                try:
                    server = db["resource_servers"][choice]
                except KeyError:
                    print("Invalid server selection")
                    continue
            name = input("Enter new name (empty to leave as \"{}\")".format(server["name"]))[:20]
            if name != "":
                server["name"] = name
            ip = input("Enter new ip (empty to leave as \"{}\")".format(server["ip"]))
            if ip != "":
                server["name"] = ip
            port = input("Enter new port (empty to leave as \"{}\")".format(server["port"]))
            if port != "":
                server["port"] = port
            write_database_to_file()

        elif choice == 'r':  # remove a resource server
            choice = int(input("Enter server number to remove: "))
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
        choice = input("Enter request (list leaderboards): ")

        if choice == "list leaderboards":
            request = request_show_leaderboards(identity, token)
            request = request_show_leaderboards(identity, token)
            writer.write(bytes(json.dumps(request) + "\n", "utf-8"))
            await writer.drain()
            response_data = await reader.readline()
            response = json.loads(response_data.decode())
            # TODO handle bad packets or error packets
            # TODO this is actually not what you get back from the resource server anymore, crashes here
            string = response["string"]  # CRASHES!
            print(string)

        elif choice == "quit":
            break

    writer.close()
    await writer.wait_closed()

if __name__ == "__main__":
    db_filename = "client_db"
    db = initialize_database()
    main()
