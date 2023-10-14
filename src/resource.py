"""
json packet contains an identity from the authentication server which has been proved
the identity has to be looked up in a table of permissions
if the person can perform the request they are making according to the table, respond with the
    answer to the request, otherwise respond with an 'access denied' packet.
"""
import socketserver
import json
from enum import IntEnum, auto
from enums import ResourceRequestType


class UserClass(IntEnum):
    User = auto()
    Moderator = auto()
    Administrator = auto()


def write_database_to_file():
    with open(db_filename, "w") as db_file:
        json.dump(db, db_file)


def initialize_database() -> dict:
    # Initialize DB either from file or with defaults
    try:
        with open(db_filename, "r") as db_file:
            db_to_return = json.load(db_file)
            print("Successfully loaded database from file.")
    except json.decoder.JSONDecodeError:
        print("Could not read db from file. Exiting to avoid corrupting!")
    except FileNotFoundError:
        print("No database found! Initializing new database. First user to connect will be granted admin.")
        # probably not necessary. database will be written to when data is added.
        #db_file = open(db_filename, "x")
        '''
        This is effectively the "standard database schema".
        At the top level, the resource server knows about "users" and "databases"
        Each of those is a list with entries.
            Each user should be a dict with "identity", "token", and "class" (admin, mod, normal) in that order.
            Each database should have a numerical identifier ("id"), a "name", and a list [] of "entries".
            # TODO dbs should have privacy associated with them
                Entries should have a "name" (typically associated with a submitting user), "score", a number, and
                    "date" referring to submission time.
        As functionality is needed, the database can be added to from here.
        '''
        db_to_return = {
            "users": [],
            "databases": [],
        }
        # Don't bother writing to file yet, wait for someone to connect
        # json.dump(db, db_file)
    return db_to_return


def response_show_leaderboards():
    # TODO trim response based on what you should be able to see
    return {
        "type": ResourceRequestType.ShowLeaderboards,
        "success": True,
        "data": db["databases"]
    }


def response_show_one_leaderboard(leaderboard_id):
    leaderboard_to_return = None
    for leaderboard in db["databases"]:
        if leaderboard["id"] == leaderboard_id:
            leaderboard_to_return = leaderboard
    # TODO account for leaderboard visibility according to user group
    return {
        "type": ResourceRequestType.ShowOneLeaderboard,
        "success": True,
        "data": leaderboard_to_return
    }


def response_create_leaderboard(leaderboard_name):
    new_leaderboard = {
        "id": len(db["databases"]),
        "name": leaderboard_name,
        "entries": []
    }
    db["databases"].append(new_leaderboard)
    return {
        "type": ResourceRequestType.CreateLeaderboard,
        "success": True,
        "data": new_leaderboard
    }


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        print("handling packet")
        self.data = self.rfile.readline().strip()
        print("data received")
        print("received {} from {}".format(self.data, self.client_address[0]))
        try:
            request = json.loads(self.data)
        except json.decoder.JSONDecodeError:
            print("Could not interpret packet!")
            return

        # If the database is currently empty (with no registered users) then the first user to connect becomes the admin
        if len(db["users"]) == 0:
            admin = {
                "identity": request["identity"],
                "token": request["token"],
                "class": UserClass.Administrator
            }
            db["users"].append(admin)
            # Save changes immediately
            write_database_to_file()

        if request["type"] == ResourceRequestType.ShowLeaderboards:
            response = response_show_leaderboards("this is the leaderboard!!!")
            self.wfile.write(json.dumps(response).encode() + b"\n")
        elif request["type"] == ResourceRequestType.ShowOneLeaderboard:
            response = response_show_one_leaderboard(request["leaderboard_id"])
            self.wfile.write(json.dumps(response).encode() + b"\n")
        elif request["type"] == ResourceRequestType.CreateLeaderboard:
            response = response_create_leaderboard(request["requested_name"])
            self.wfile.write(json.dumps(response).encode() + b"\n")


if __name__ == "__main__":
    # TODO get this from command line or config file?
    db_filename = "res_db"

    db = initialize_database()

    HOST, PORT = "localhost", 8086
    with socketserver.TCPServer((HOST, PORT), Handler) as server:
        server.serve_forever()
