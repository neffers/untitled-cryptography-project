"""
json packet contains an identity from the authentication server which has been proved
the identity has to be looked up in a table of permissions
if the person can perform the request they are making according to the table, respond with the
    answer to the request, otherwise respond with an 'access denied' packet.
"""
import socketserver
import json
import sqlite3
import time
from os import path
from enum import IntEnum, auto
from enums import ResourceRequestType


class Permissions(IntEnum):
    # we want these to have a specific hierarchy
    NoAccess = 0
    Read = 1
    Write = 2
    Moderate = 3


class UserClass(IntEnum):
    User = Permissions.NoAccess
    Administrator = Permissions.Moderate


def initialize_database():
    # Initialize DB either from file or with defaults
    if path.exists(db_filename):
        print("Found existing database. Loading from there.")
        return sqlite3.connect(db_filename)
    else:
        print("Did not find a database. Initializing new database from schema...")
        sqldb = sqlite3.connect(db_filename)
        dbcursor = sqldb.cursor()

        enable_foreign_keys = "PRAGMA foreign_keys = ON;"
        dbcursor.execute(enable_foreign_keys)

        # The base database schema
        database_initialization_command = """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            identity TEXT UNIQUE,
            token TEXT,
            class INTEGER,
            registration_date INTEGER
        );
        CREATE TABLE leaderboards (
            id INTEGER PRIMARY KEY,
            name TEXT,
            creation_date INTEGER,
            default_permission INTEGER,
            ascending INTEGER
        );
        CREATE TABLE permissions (
            user INTEGER REFERENCES users(id),
            leaderboard INTEGER REFERENCES  leaderboards(id),
            permission INTEGER,
            change_date INTEGER
        );
        CREATE TABLE leaderboard_entries (
            id INTEGER PRIMARY KEY,
            user INTEGER REFERENCES users(id),
            leaderboard INTEGER REFERENCES leaderboards(id),
            score REAL,
            submission_date INTEGER,
            verified INTEGER,
            verification_date INTEGER,
            verifier INTEGER REFERENCES users(id)
        );
        CREATE TABLE entry_comments (
            id INTEGER PRIMARY KEY,
            user INTEGER REFERENCES users(id),
            entry INTEGER REFERENCES leaderboard_entries(id),
            date REAL,
            content TEXT
        );
        CREATE TABLE files (
            id INTEGER PRIMARY KEY,
            entry INTEGER REFERENCES leaderboard_entries(id),
            name TEXT,
            submission_date INTEGER,
            data BLOB
        );
        """
        dbcursor.executescript(database_initialization_command)
        dbcursor.close()
        return sqldb


# Returns Permissions.NoAccess if no permission is found (including if user is a guest)
# Deprecated
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

    sql_cur = db.cursor()

    # Make sure we have any administrators, create user as admin if not
    get_admins_command = "SELECT * FROM users WHERE class = ?"
    sql_cur.execute(get_admins_command, (UserClass.Administrator,))
    admins = sql_cur.fetchall()
    if len(admins) == 0:
        print("No admin found, adding newly connected user to admin list")
        create_admin_command = "INSERT INTO users(identity, token, class) VALUES(?, ?, ?)"
        admin_params = (identity, token, UserClass.Administrator)
        sql_cur.execute(create_admin_command, admin_params)
        db.commit()

    get_user_command = "SELECT * FROM users WHERE identity = ?"
    user = sql_cur.execute(get_user_command, (identity,)).fetchone()

    if user is not None:
        print("Found user:")
        print(user)
    else:
        # Register user automatically
        print("User not previously registered! Registering...")
        insert_user_command = "INSERT INTO users(identity, token, class, registration_date) VALUES(?,?,?,?)"
        insert_user_params = (identity, token, UserClass.User, int(time.time()))
        sql_cur.execute(insert_user_command, insert_user_params)
        user = sql_cur.execute(get_user_command, (identity,)).fetchone()
    userid = user[0]

    if request_type == ResourceRequestType.ShowLeaderboards:
        # TODO can this be simplified?
        get_leaderboards_command = """
            select l.id, l.name, max(l.default_permission, coalesce(p.permission, 0), class) as perm
            from leaderboards l
                left join (select * from permissions where user = ?) p on l.id = p.leaderboard
                inner join (select class from users where id = ?)
            where perm >= ?
        """
        get_leaderboards_params = (userid, userid, Permissions.Read)
        sql_cur.execute(get_leaderboards_command, get_leaderboards_params)
        leaderboards_to_return = sql_cur.fetchall()
        return {
            "success": True,
            "data": leaderboards_to_return
        }

    if request_type == ResourceRequestType.ShowOneLeaderboard:
        try:
            leaderboard_id = request["leaderboard_id"]
            leaderboard = db["leaderboards"][leaderboard_id]
        except KeyError:
            return return_bad_request("Didn't include leaderboard id, or requested invalid leaderboard")
        data_to_return = {
            "id": leaderboard["id"],
            "name": leaderboard["name"],
            "entries": [entry for entry in leaderboard["entries"] if entry["verified"]]
        }
        permission = get_leaderboard_permission(identity, leaderboard_id)
        if leaderboard["visible"] or permission >= Permissions.Read:
            return {
                "success": True,
                "data": data_to_return,
            }
        else:
            # I don't figure it is a problem to tell the user that the leaderboard exists.
            return return_bad_request("You do not have permission to view that leaderboard.")

    if request_type == ResourceRequestType.CreateLeaderboard:
        if user["class"] != UserClass.Administrator:
            return return_bad_request("You do not have permission to do that.")
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
        try:
            leaderboard_id = request["leaderboard_id"]
            if get_leaderboard_permission(identity, leaderboard_id) <= Permissions.Write:
                return return_bad_request("You do not have permission to do that.")
            new_entry = {
                "name": identity,
                "score": request["score"],
                "date": time.time(),
                "verified": False,
                "comments": [{
                    "identity": identity,
                    "date": time.time(),
                    "content": request["comment"],
                }],
            }
            db["leaderboards"][leaderboard_id].append(new_entry)
            write_database_to_file()
            return {
                "success": True,
                "data": new_entry,
            }
        except KeyError:
            return return_bad_request("Bad leaderboard ID, or didn't include score. Must also provide a comment.")


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
