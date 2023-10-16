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
            date INTEGER,
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


# Generally used as (lb_id, lb_name, lb_perm, lb_asc) = get_leaderboard_info()
def get_leaderboard_info(userid, leaderboard_id):
    cur = db.cursor()
    # TODO ugly, make it so we don't need to duplicate userid in params?
    get_leaderboard_info_command = """
        select l.id, l.name, max(l.default_permission, coalesce(p.permission, 0), class) as perm, l.ascending
        from leaderboards l
            left join (select * from permissions where user = ?) p on l.id = p.leaderboard
            inner join (select class from users where id = ?)
        where l.id = ?
    """
    get_leaderboard_info_params = (userid, userid, leaderboard_id)
    cur.execute(get_leaderboard_info_command, get_leaderboard_info_params)
    ret_tuple = cur.fetchone()
    cur.close()
    return ret_tuple


def return_bad_request(further_info=""):
    return {
        "success": False,
        "data": "Malformed request. " + further_info,
    }


def handle_request(request):
    # Every request needs to have these
    try:
        request_type = request["type"]
        request_identity = request["identity"]
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
        admin_params = (request_identity, token, UserClass.Administrator)
        sql_cur.execute(create_admin_command, admin_params)
        db.commit()

    get_user_command = "SELECT * FROM users WHERE identity = ?"
    requesting_user = sql_cur.execute(get_user_command, (request_identity,)).fetchone()

    if requesting_user is not None:
        print("Found user:")
        print(requesting_user)
    else:
        # Register user automatically
        print("User not previously registered! Registering...")
        insert_user_command = "INSERT INTO users(identity, token, class, registration_date) VALUES(?,?,?,?)"
        insert_user_params = (request_identity, token, UserClass.User, int(time.time()))
        sql_cur.execute(insert_user_command, insert_user_params)
        requesting_user = sql_cur.execute(get_user_command, (request_identity,)).fetchone()
    # Can be used throughout the request handling
    (request_user_id, request_identity, token, user_class, user_reg_date) = requesting_user

    # Basic: List Leaderboards
    if request_type == ResourceRequestType.ListLeaderboards:
        # TODO can this be simplified?
        get_leaderboards_command = """
            select l.id, l.name, max(l.default_permission, coalesce(p.permission, 0), class) as perm
            from leaderboards l
                left join (select * from permissions where user = ?) p on l.id = p.leaderboard
                inner join (select class from users where id = ?)
            where perm >= ?
        """
        get_leaderboards_params = (request_user_id, request_user_id, Permissions.Read)
        sql_cur.execute(get_leaderboards_command, get_leaderboards_params)
        leaderboards_to_return = sql_cur.fetchall()
        return {
            "success": True,
            "data": leaderboards_to_return
        }

    # Basic: Open Leaderboard
    # Leaderboard: List Entries
    if request_type == ResourceRequestType.ShowOneLeaderboard:
        # Parse request
        try:
            leaderboard_id = request["leaderboard_id"]
        except KeyError:
            return return_bad_request("Didn't include leaderboard id")

        # make sure leaderboard should be visible by user
        (leaderboard_id, leaderboard_name, permission, ascending) = (
            get_leaderboard_info(request_user_id, leaderboard_id))
        if permission < 1:
            return return_bad_request("You don't have permission to view that.")

        # TODO this doesn't list all entries for moderators
        get_entries_command = """
            select e.id, user, u.identity, score, submission_date
                from leaderboard_entries e
                join main.leaderboards l on e.leaderboard = l.id
                join main.users u on e.user = u.id
            where (verified or user = ?) and l.id = ?
            order by score desc
        """
        get_entries_params = (request_user_id, leaderboard_id)
        sql_cur.execute(get_entries_command, get_entries_params)
        entries = sql_cur.fetchall()
        if ascending:
            entries.reverse()
        data_to_return = {
            "id": leaderboard_id,
            "name": leaderboard_name,
            "entries": entries
        }
        return {
            "success": True,
            "data": data_to_return,
        }  

    # Basic: Add Leaderboard
    if request_type == ResourceRequestType.CreateLeaderboard:
        if user_class != UserClass.Administrator:
            return return_bad_request("You do not have permission to do that.")
        try:
            new_lb_name = request["leaderboard_name"]
            new_lb_perm = max(min(request["leaderboard_permission"], Permissions.Moderate), Permissions.NoAccess)
            new_lb_asc = request["leaderboard_ascending"]
        except KeyError:
            return return_bad_request("Didn't include new leaderboard name, default permission, or ascending bool")
        new_lb_command = """
            insert into leaderboards(name, creation_date, default_permission, ascending) values(?,?,?,?)
        """
        new_lb_params = (new_lb_name, int(time.time()), new_lb_perm, new_lb_asc)
        sql_cur.execute(new_lb_command, new_lb_params)
        db.commit()
        new_lb_id = sql_cur.lastrowid
        return {
            "success": True,
            "data": new_lb_id,
        }

    # Leaderboard: Submit Entry
    if request_type == ResourceRequestType.AddEntry:
        try:
            leaderboard_id = request["leaderboard_id"]
            entry_score = request["score"]
            comment = request["comment"]
        except KeyError:
            return return_bad_request("request must include leaderboard id, score, and comment")
        # error if leaderboard id doesn't exist
        try:
            (lb_id, lb_name, lb_perm, lb_asc) = get_leaderboard_info(request_user_id, leaderboard_id)
        except TypeError:
            return return_bad_request("That leaderboard does not exist")
        # error if you don't have permission to write to it
        if lb_perm < Permissions.Write:
            return return_bad_request("You do not have permission to do that")
        create_entry_command = """
            insert into leaderboard_entries(user, leaderboard, score, submission_date, verified)
            values(?,?,?,?,?)
        """
        create_entry_params = (request_user_id, leaderboard_id, entry_score, int(time.time()), 0)
        sql_cur.execute(create_entry_command, create_entry_params)
        entry_id = sql_cur.lastrowid
        create_comment_command = """
            insert into entry_comments(user, entry, date, content)
            values(?,?,?,?)
        """
        create_comment_params = (request_user_id, entry_id, int(time.time()), comment)
        sql_cur.execute(create_comment_command, create_comment_params)
        db.commit()
        comment_id = sql_cur.lastrowid
        return {
            "success": True,
            "data": entry_id,
        }

    # Basic: List Users
    # TODO: Does this fulfill Basic: Open user and Basic: open self?
    if request_type == ResourceRequestType.ListUsers:
        get_users_command = """
            select id, identity
                from users
            order by id
        """
        sql_cur.execute(get_users_command)
        return {
            "success": True,
            "data": sql_cur.fetchall(),
        }

    # Leaderboard: List Unverified
    if request_type == ResourceRequestType.ListUnverified:
        try:
            leaderboard_id = request["leaderboard_id"]
        except KeyError:
            return return_bad_request("Did not include a leaderboard id")

        list_unverified_command = """
            select e.id, user, identity, score, submission_date
            from leaderboard_entries e
                     left outer join leaderboards l on e.leaderboard = l.id
                     left outer join (select u.class, u.identity
                                      from users u
                                      where u.id = ?)
                     left outer join (select p.permission, p.leaderboard
                                      from users u
                                               left join permissions p on p.user = u.id
                                      where u.id = ?) x
                                     on e.leaderboard = x.leaderboard
            where (user = ? or max(default_permission, class, coalesce(permission, 0)) >= 3) and not verified
              and e.leaderboard = ?
        """
        list_unverified_params = (request_user_id, request_user_id, request_user_id, leaderboard_id)
        sql_cur.execute(list_unverified_command, list_unverified_params)

        entries = sql_cur.fetchall()
        return {
            "success": True,
            "data": entries,
        }

    # Leaderboard: Open Entry
    # Entry: View Entry
    # Entry: View Comments
    # User: Open Submission
    if request_type == ResourceRequestType.GetEntry:
        try:
            entry_id = request["entry_id"]
        except KeyError:
            return return_bad_request("Must include an entry ID.")
        # TODO check permission
        get_entry_command = """
            select e.id, user, u.identity, score, submission_date, verified, verifier, v.identity
            from leaderboard_entries e
            left join main.users u on e.user = u.id
            left join main.users v on e.verifier = v.id
            where e.id = ?
        """
        get_entry_params = (entry_id,)
        sql_cur.execute(get_entry_command, get_entry_params)
        entry = sql_cur.fetchone()

        get_comments_command = """
            select u.identity, date, content
            from entry_comments c
            left join main.users u on u.id = c.user
            where c.entry = ?
        """
        get_comments_params = (entry_id,)
        sql_cur.execute(get_comments_command, get_comments_params)
        comments = sql_cur.fetchall()

        get_files_command = """
            select id, name, submission_date
            from files
            where entry = ?
        """
        get_files_params = (entry_id,)
        sql_cur.execute(get_files_command, get_files_params)
        files = sql_cur.fetchall()

        data_to_return = {
            "entry": entry,
            "comments": comments,
            "files": files,
        }
        return {
            "success": True,
            "data": data_to_return,
        }
    
    # User: View User (get visible entries)
    if request_type == ResourceRequestType.ViewUser:
        #TODO: Reject access if permission is NoAccess
        # From Jordan: As it stands, there's no way for this to be rejected.
        # There's no permission gate on viewing the user, but the *entries* should be filtered
        # based on what should be visible to the requesting user
        try:
            user_id = request["user_id"]
        except KeyError:
            return return_bad_request("Must include a user ID.")
        
        get_user_command = """
            select identity, registration_date
                from users
            where id = ?
        """
        get_user_params = (user_id,)
        sql_cur.execute(get_user_command, get_user_params)
        user_data = sql_cur.fetchone()

        get_entries_command = """
            select e.id, e.leaderboard, e.score, e.submission_date
            from leaderboard_entries e
            left outer join leaderboards l on e.leaderboard = l.id
            left outer join (select u.class
                             from users u
                             where u.id = ?)
            left outer join (select p.permission, p.leaderboard
                             from users u
                             left join permissions p on p.user = u.id
                             where u.id = ?) x
                on e.leaderboard = x.leaderboard
            where (verified or (max(default_permission, class, coalesce(permission, 0)) >= ?) or e.user = ?)
                and (e.user = ?)
        """
        get_entries_params = (request_user_id, request_user_id, Permissions.Moderate, request_user_id, user_id)
        sql_cur.execute(get_entries_command, get_entries_params)
        entries = sql_cur.fetchall()

        data_to_return = {
            "user_data": user_data,
            "entries": entries,
        }
        return {
            "success": True,
            "data": data_to_return,
        }

    # Entry: Verify Entry
    # Entry: Unverify Entry
    if request_type == ResourceRequestType.ModifyEntryVerification:
        try:
            entry_id = request["entry_id"]
            verified = request["verified"]
        except KeyError:
            return return_bad_request("Must include entry_id and verification bool")
        get_entry_command = """
            select leaderboard, verified
            from leaderboard_entries
            where id = ?
        """
        get_entry_params = (entry_id,)
        sql_cur.execute(get_entry_command, get_entry_params)
        try:
            (leaderboard_id, entry_verified) = sql_cur.fetchone()
        except TypeError:
            return return_bad_request("The specified entry does not exist")

        (lb_id, lb_name, lb_perm, lb_asc) = get_leaderboard_info(request_user_id, leaderboard_id)

        if lb_perm < Permissions.Moderate:
            return return_bad_request("You do not have permission to do that")

        if verified and entry_verified:
            return return_bad_request("That entry has already been verified")
        if not verified and not entry_verified:
            return return_bad_request("That entry is already not verified")

        modify_entry_command = """
            update leaderboard_entries
            set verified = ?, verifier = ?, verification_date = ?
            where id = ?
        """
        modify_entry_params = (verified, request_user_id, int(time.time()), entry_id)
        sql_cur.execute(modify_entry_command, modify_entry_params)
        db.commit()
        return {
            "success": True,
            "data": None,
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
