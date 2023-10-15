"""
json packet contains an identity from the authentication server which has been proved
the identity has to be looked up in a table of permissions
if the person can perform the request they are making according to the table, respond with the
    answer to the request, otherwise respond with an 'access denied' packet.
"""
import socketserver
import json
from datetime import datetime
from enum import IntEnum, auto
from enums import ResourceRequestType


class UserClass(IntEnum):
    User = auto()
    Administrator = auto()


class Permissions(IntEnum):
    # we want these to have a specific hierarchy
    NoAccess = 0
    Read = 1
    Write = 2
    Moderate = 3


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
        # db_file = open(db_filename, "x")
        '''
        This is effectively the "standard database schema".
        At the top level, the resource server knows about "users", "groups" and "leaderboards", each a list.
            Each user should be a dict with:
                "identity",
                "token",
                "class" (admin, mod, normal),
                and "permissions", a list [] of dicts containing:
                    "id", the associated leaderboard,
                    "level": a Permission enum
            Each leaderboard should have:
                "id", a numerical identifier corresponding to position in list,
                "name",
                "visible", a default visibility,
                "entries", a list [] of entries,
        As functionality is needed, the database can be added to from here.
        '''
        db_to_return = {
            "users": [],
            "leaderboards": [],
        }
        # Don't bother writing to file yet, wait for someone to connect
        # json.dump(db, db_file)
    return db_to_return


# Returns Permissions.NoAccess if no permission is found (including if user is a guest)
def get_leaderboard_permission(identity, leaderboard_id):
    try:
        user = [user for user in db["users"] if user["identity"] == identity][0]
    except KeyError:
        user = {}  # User is not registered
    try:
        return [perm["level"] for perm in user["permissions"] if perm["id"] == leaderboard_id][0]
    except KeyError:
        return Permissions.NoAccess


def return_bad_request(further_info=""):
    return {
        "success": False,
        "data": "Malformed request. " + further_info,
    }


def handle_request(request):
    # Every request needs to have these
    try:
        request_type = request["type"]
        identity = request["identity"]
        token = request["token"]
    except KeyError:
        return return_bad_request("Didn't include request type, identity, or token")

    try:
        user = [user for user in db["users"] if user["identity"] == identity][0]
    except KeyError:
        user = {}  # User is unregistered, a 'guest'

    if request_type == ResourceRequestType.ShowLeaderboards:
        leaderboards_to_return = []
        for leaderboard in db["leaderboards"]:
            append = False
            if user.get("class") == UserClass.Administrator or leaderboard["visible"]:
                append = True
            else:
                permission = get_leaderboard_permission(identity, leaderboard["id"])
                if permission >= Permissions.Read:
                    append = True
            if append:
                leaderboards_to_return.append(
                    {k: leaderboard[k] for k in leaderboard if k not in ("entries", "visible")})
        return {
            "success": True,
            "data": leaderboards_to_return
        }

    if request_type == ResourceRequestType.ShowOneLeaderboard:
        # TODO: Trim unverified entries from leaderboard
        try:
            leaderboard_id = request["leaderboard_id"]
            leaderboard = db["leaderboards"][leaderboard_id]
        except KeyError:
            return return_bad_request("Didn't include leaderboard id, or requested invalid leaderboard")
        permission = get_leaderboard_permission(identity, leaderboard_id)
        if leaderboard["visible"] or permission >= Permissions.Read:
            return {
                "success": True,
                "data": leaderboard
            }
        else:
            # I don't figure it is a problem to tell the user that the leaderboard exists.
            return return_bad_request("You do not have permission to view that leaderboard.")

    if request_type == ResourceRequestType.CreateLeaderboard:
        # TODO account for user roles, check for duplicate names?
        try:
            new_leaderboard = {
                "id": len(db["leaderboards"]),
                "name": request["leaderboard_name"],
                "entries": [],
                "visible": request["leaderboard_visibility"]
            }
            db["leaderboards"].append(new_leaderboard)
            write_database_to_file()
            return {
                "success": True,
                "data": new_leaderboard
            }
        except KeyError:
            return return_bad_request("Didn't include new leaderboard name, or leaderboard visibility")

    if request_type == ResourceRequestType.AddEntry:
        # TODO check user privileges
        try:
            leaderboard_id = request["leaderboard_id"]
            new_entry = {
                "name": identity,
                "score": request["score"],
                "date": datetime.utcnow(),
            }
            db["leaderboards"][leaderboard_id].append(new_entry)
            write_database_to_file()
            return {
                "success": True,
                "data": db["leaderboards"][leaderboard_id],
            }
        except KeyError:
            return return_bad_request("Bad leaderboard ID, or didn't include score.")


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
            response = return_bad_request("Could not interpret packet.")
            print("sending {}".format(response))
            self.wfile.write(json.dumps(response).encode() + b"\n")
            return

        # If the database is currently empty (with no registered users) then the first user to connect becomes the admin
        if len(db["users"]) == 0:
            admin = {
                "identity": request["identity"],
                "token": request["token"],
                "class": UserClass.Administrator,
                "permissions": [],  # Shouldn't matter since admin class should overrule all permissions
            }
            db["users"].append(admin)
            # Save changes immediately
            write_database_to_file()

        response = handle_request(request)
        print("sending {}".format(response))
        self.wfile.write(json.dumps(response).encode() + b"\n")


if __name__ == "__main__":
    # TODO get this from command line or config file?
    db_filename = "res_db"

    db = initialize_database()

    HOST, PORT = "localhost", 8086
    with socketserver.TCPServer((HOST, PORT), Handler) as server:
        server.serve_forever()
