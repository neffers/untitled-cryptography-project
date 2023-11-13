import os
import socketserver
import sqlite3
import time
import base64
import signal
import sys
from os import path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import src.serverlib
import src.cryptolib
import src.netlib
from enums import ResourceRequestType, Permissions, UserClass


# Generally used as (lb_id, lb_name, lb_perm, lb_asc) = get_leaderboard_info()
def get_leaderboard_info(userid, leaderboard_id):
    cur = db.cursor()
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


def bad_request_json(further_info=""):
    return {
        "success": False,
        "data": "Bad request. " + further_info,
    }


def list_leaderboards_response(requesting_user_id: int):
    cursor = db.cursor()
    get_leaderboards_command = """
        select l.id, l.name, max(l.default_permission, coalesce(p.permission, 0), class) as perm
        from leaderboards l
            left join (select * from permissions where user = ?) p on l.id = p.leaderboard
            inner join (select class from users where id = ?)
        where perm >= ?
    """
    get_leaderboards_params = (requesting_user_id, requesting_user_id, Permissions.Read)
    cursor.execute(get_leaderboards_command, get_leaderboards_params)
    leaderboards_to_return = cursor.fetchall()
    return {
        "success": True,
        "data": leaderboards_to_return
    }


def show_one_leaderboard_response(requesting_user_id, leaderboard_id):
    cursor = db.cursor()
    # make sure leaderboard should be visible by user
    (leaderboard_id, leaderboard_name, permission, ascending) = (
        get_leaderboard_info(requesting_user_id, leaderboard_id))
    if permission < Permissions.Read:
        return bad_request_json("You don't have permission to view that.")
    # If moderator, return all entries
    if permission >= Permissions.Moderate:
        get_entries_command = """
            select e.id, user, u.identity, score, submission_date, verified
                from leaderboard_entries e
                join main.leaderboards l on e.leaderboard = l.id
                join main.users u on e.user = u.id
            where l.id = ?
            order by score desc
        """
        get_entries_params = (leaderboard_id,)
    else:
        # Non-mods get visible entries and those that they submitted
        get_entries_command = """
            select e.id, user, u.identity, score, submission_date, verified
                from leaderboard_entries e
                join main.leaderboards l on e.leaderboard = l.id
                join main.users u on e.user = u.id
            where (verified or user = ?) and l.id = ?
            order by score desc
        """
        get_entries_params = (requesting_user_id, leaderboard_id)

    cursor.execute(get_entries_command, get_entries_params)
    entries = cursor.fetchall()
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


def handle_request(request):
    # Every request needs to have these
    try:
        request_type = request["type"]
        request_identity = request["identity"]
        token = request["token"]
    except KeyError:
        return bad_request_json("Didn't include request type, identity, or token")

    sql_cur = db.cursor()

    # Make sure we have any administrators, create user as admin if not
    get_admins_command = "SELECT * FROM users WHERE class = ?"
    sql_cur.execute(get_admins_command, (UserClass.Administrator,))
    admins = sql_cur.fetchall()
    if len(admins) == 0:
        print("No admin found, adding newly connected user to admin list")
        create_admin_command = "INSERT INTO users(identity, token, class, registration_date) VALUES(?, ?, ?, ?)"
        admin_params = (request_identity, token, UserClass.Administrator, int(time.time()))
        sql_cur.execute(create_admin_command, admin_params)
        db.commit()

    get_user_command = "SELECT * FROM users WHERE identity = ?"
    requesting_user = sql_cur.execute(get_user_command, (request_identity,)).fetchone()

    if requesting_user is not None:
        print("Found user:", requesting_user)
    else:
        # Register user automatically
        print("User not previously registered! Registering...")
        # TODO: Eventually, this should make request to authentication server to verify token?
        insert_user_command = "INSERT INTO users(identity, token, class, registration_date) VALUES(?,?,?,?)"
        insert_user_params = (request_identity, token, UserClass.User, int(time.time()))
        sql_cur.execute(insert_user_command, insert_user_params)
        db.commit()
        requesting_user = sql_cur.execute(get_user_command, (request_identity,)).fetchone()
    # Can be used throughout the request handling
    (request_user_id, request_identity, token, user_class, user_reg_date) = requesting_user

    # Get public key
    if request_type == ResourceRequestType.PublicKey:
        return src.serverlib.public_key_response(public_key)

    # Basic: List Leaderboards
    if request_type == ResourceRequestType.ListLeaderboards:
        return list_leaderboards_response(request_user_id)

    # Basic: Open Leaderboard
    # Leaderboard: List Entries
    if request_type == ResourceRequestType.ShowOneLeaderboard:
        # Parse request
        try:
            leaderboard_id = request["leaderboard_id"]
        except KeyError:
            return bad_request_json("Must include leaderboard id.")

        if type(leaderboard_id) is not int:
            return bad_request_json("leaderboard_id must be an int.")
        return show_one_leaderboard_response(request_user_id, leaderboard_id)

    # Basic: Add Leaderboard
    if request_type == ResourceRequestType.CreateLeaderboard:
        if user_class != UserClass.Administrator:
            return bad_request_json("You do not have permission to do that.")
        try:
            new_lb_name = request["leaderboard_name"]
            if type(request["leaderboard_permission"]) is not int:
                return bad_request_json("leaderboard_permission must be an int.")
            new_lb_perm = max(min(request["leaderboard_permission"], Permissions.Moderate), Permissions.NoAccess)
            new_lb_asc = request["leaderboard_ascending"]
        except KeyError:
            return bad_request_json("Didn't include new leaderboard name, default permission, or ascending bool")

        if type(new_lb_name) is not str:
            return bad_request_json("leaderboard_name must be a string.")
        if type(new_lb_asc) is not bool:
            return bad_request_json("leaderboard_ascending must be a bool.")

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
            return bad_request_json("Request must include leaderboard id, score, and comment.")

        if type(leaderboard_id) is not int:
            return bad_request_json("leaderboard_id must be an int.")
        if type(entry_score) is not int and type(entry_score) is not float:
            return bad_request_json("score must be a number.")
        if type(comment) is not str:
            return bad_request_json("comment must be a string.")

        # error if leaderboard id doesn't exist
        try:
            (lb_id, lb_name, lb_perm, lb_asc) = get_leaderboard_info(request_user_id, leaderboard_id)
        except TypeError:
            return bad_request_json("That leaderboard does not exist.")
        # error if you don't have permission to write to it
        if lb_perm < Permissions.Write:
            return bad_request_json("You do not have permission to do that.")
        create_entry_command = """
            insert into leaderboard_entries(user, leaderboard, score, submission_date, verified)
            values(?,?,?,?,?)
        """
        create_entry_params = (request_user_id, leaderboard_id, entry_score, int(time.time()), False)
        try:
            sql_cur.execute(create_entry_command, create_entry_params)
        except sqlite3.IntegrityError:
            return bad_request_json("Leaderboard does not exist.")
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
    if request_type == ResourceRequestType.ListUsers:
        get_users_command = """
            select id, identity
                from users
            order by id
        """
        sql_cur.execute(get_users_command)
        users = sql_cur.fetchall()
        return {
            "success": True,
            "data": users,
        }

    # Leaderboard: List Unverified
    if request_type == ResourceRequestType.ListUnverified:
        try:
            leaderboard_id = request["leaderboard_id"]
        except KeyError:
            return bad_request_json("Must include a leaderboard id.")

        if type(leaderboard_id) is not int:
            return bad_request_json("leaderboard_id must be an int.")

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
            return bad_request_json("Must include an entry ID.")

        if type(entry_id) is not int:
            return bad_request_json("entry_id must be an int.")

        # Check permissions by first getting leaderboard id and then getting requesting user's perms for it
        get_leaderboard_id_command = """
            select user, leaderboard, verified
            from leaderboard_entries
            where id = ?
        """
        get_leaderboard_id_params = (entry_id,)
        sql_cur.execute(get_leaderboard_id_command, get_leaderboard_id_params)
        try:
            (submitter, leaderboard_id, verified) = sql_cur.fetchone()
        except TypeError:
            return bad_request_json("That entry does not exist.")
        (lb_id, lb_name, lb_perm, lb_asc) = get_leaderboard_info(request_user_id, leaderboard_id)
        if (verified and lb_perm >= Permissions.Read) or (
                not verified and (submitter == request_user_id or lb_perm >= Permissions.Moderate)):
            pass
        else:
            return bad_request_json("You do not have permission to view that.")

        get_entry_command = """
            select e.id, user, u.identity, score, submission_date, verified, verifier, v.identity, verification_date
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
            order by date
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
    # Basic: Open user
    # Basic: open self
    if request_type == ResourceRequestType.ViewUser:
        try:
            user_id = request["user_id"]
        except KeyError:
            return bad_request_json("Must include a user ID.")

        if type(user_id) is not int:
            return bad_request_json("user_id must be an int.")

        get_user_command = """
            select identity, registration_date
                from users
            where id = ?
        """
        get_user_params = (user_id,)
        sql_cur.execute(get_user_command, get_user_params)
        user_data = sql_cur.fetchone()
        if user_data is None:
            return bad_request_json("That user doesn't exist.")

        get_entries_command = """
            select e.id, e.leaderboard, e.score, e.verified, e.submission_date
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

    # Internal
    if request_type == ResourceRequestType.GetIdFromIdentity:
        try:
            identity = request["identity"]
        except KeyError:
            return bad_request_json("Must include an identity.")

        if type(identity) is not str:
            return bad_request_json("identity must be a string.")

        get_user_command = "SELECT id FROM users WHERE identity = ?"
        get_user_params = (identity,)
        sql_cur.execute(get_user_command, get_user_params)
        user_id = sql_cur.fetchone()
        if user_id is None:
            return bad_request_json("That user doesn't exist.")

        return {
            "success": True,
            "data": user_id,
        }

    # Entry: Verify Entry
    # Entry: Unverify Entry
    if request_type == ResourceRequestType.ModifyEntryVerification:
        try:
            entry_id = request["entry_id"]
            verified = request["verified"]
        except KeyError:
            return bad_request_json("Must include entry_id and verification bool.")

        if type(entry_id) is not int:
            return bad_request_json("entry_id must be an int.")
        if type(verified) is not bool:
            return bad_request_json("verified must be a bool.")

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
            return bad_request_json("The specified entry does not exist.")

        (lb_id, lb_name, lb_perm, lb_asc) = get_leaderboard_info(request_user_id, leaderboard_id)

        if lb_perm < Permissions.Moderate:
            return bad_request_json("You do not have permission to do that.")

        if verified and entry_verified:
            return bad_request_json("That entry has already been verified.")
        if not verified and not entry_verified:
            return bad_request_json("That entry is already not verified.")

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

    # Entry: Add comment
    if request_type == ResourceRequestType.AddComment:
        try:
            entry_id = request["entry_id"]
            content = request["content"]
        except KeyError:
            return bad_request_json("Must include entry id and comment content.")

        if type(entry_id) is not int:
            return bad_request_json("entry_id must be an int.")
        if type(content) is not str:
            return bad_request_json("content must be a string.")

        # Check permissions by first getting leaderboard id and then getting requesting user's perms for it
        get_leaderboard_id_command = """
            select user, leaderboard, verified
            from leaderboard_entries
            where id = ?
        """
        get_leaderboard_id_params = (entry_id,)
        sql_cur.execute(get_leaderboard_id_command, get_leaderboard_id_params)
        try:
            (submitter, leaderboard_id, verified) = sql_cur.fetchone()
        except TypeError:
            return bad_request_json("That entry does not exist.")
        (lb_id, lb_name, lb_perm, lb_asc) = get_leaderboard_info(request_user_id, leaderboard_id)
        if not (request_user_id == submitter or lb_perm >= Permissions.Moderate):
            return bad_request_json("You do not have permission to do that.")

        add_comment_command = """
            insert into entry_comments(user, entry, date, content)
                values (?,?,?,?)
        """
        add_comment_params = (request_user_id, entry_id, int(time.time()), content)
        try:
            sql_cur.execute(add_comment_command, add_comment_params)
        except sqlite3.IntegrityError:
            return bad_request_json("Entry does not exist.")
        db.commit()
        return {
            "success": True,
            "data": None,
        }

    # Admin: Remove Leaderboard
    if request_type == ResourceRequestType.RemoveLeaderboard:
        if user_class != UserClass.Administrator:
            return bad_request_json("You do not have permission to do that.")
        try:
            ldb_id = request["leaderboard_id"]
        except KeyError:
            return bad_request_json("Must include leaderboard id.")

        if type(ldb_id) is not int:
            return bad_request_json("leaderboard_id must be an int.")

        remove_lbd = """
            delete from leaderboards where id = ?
        """
        sql_cur.execute(remove_lbd, (ldb_id,))
        db.commit()
        return {
            "success": True,
            "data": None
        }

    # Entry: Remove Entry
    if request_type == ResourceRequestType.RemoveEntry:
        try:
            entry_id = request["entry_id"]
        except KeyError:
            return bad_request_json("Must include entry id.")

        if type(entry_id) is not int:
            return bad_request_json("entry_id must be an int.")

        get_submitter_command = """
            select user
            from leaderboard_entries
            where id = ?
        """
        get_submitter_params = (entry_id,)
        sql_cur.execute(get_submitter_command, get_submitter_params)
        (submitter,) = sql_cur.fetchone()

        if user_class < UserClass.Administrator and submitter != request_user_id:
            return bad_request_json("You do not have permission to do that.")

        remove_entry = """
            delete from leaderboard_entries where id = ?
        """
        sql_cur.execute(remove_entry, (entry_id,))
        db.commit()
        return {
            "success": True,
            "data": None
        }

    # User: View Permissions
    if request_type == ResourceRequestType.ViewPermissions:
        if user_class < UserClass.Administrator:
            return bad_request_json("You don't have permission to do that.")
        try:
            user_id = request["user_id"]
        except KeyError:
            return bad_request_json("Must include user id.")

        if type(user_id) is not int:
            return bad_request_json("user_id must be an int.")

        view_permissions_command = "SELECT leaderboard, permission FROM permissions WHERE user = ?"
        sql_cur.execute(view_permissions_command, (user_id,))
        permissions = sql_cur.fetchall()
        return {
            "success": True,
            "data": permissions,
        }

    # User: Set Permission
    if request_type == ResourceRequestType.SetPermission:
        if user_class < UserClass.Administrator:
            return bad_request_json("You don't have permission to do that.")
        try:
            user_id = request["user_id"]
            ldb_id = request["leaderboard_id"]
            p = request["permission"]
        except KeyError:
            return bad_request_json("Must include user id, leaderboard id, and permission.")

        if type(user_id) is not int:
            return bad_request_json("user_id must be an int.")
        if type(ldb_id) is not int:
            return bad_request_json("leaderboard_id must be an int.")
        if type(p) is not int or p < Permissions.NoAccess or p > Permissions.Moderate:
            return bad_request_json("permission must be an int and between {} and {}.".format(
                Permissions.NoAccess, Permissions.Moderate))

        delete_old_permissions_command = """
            delete
            from permissions
            where user = ? and leaderboard = ?
        """
        delete_old_permissions_params = (user_id, ldb_id)
        sql_cur.execute(delete_old_permissions_command, delete_old_permissions_params)

        set_permission_command = """
            insert
            into permissions (user, leaderboard, permission, change_date)
            values (?,?,?,?)
        """
        set_permission_params = (user_id, ldb_id, p, int(time.time()))
        try:
            sql_cur.execute(set_permission_command, set_permission_params)
        except sqlite3.IntegrityError:
            return bad_request_json("Specified user or leaderboard does not exist.")
        db.commit()
        return {
            "success": True,
            "data": None
        }

    # User: Remove User
    if request_type == ResourceRequestType.RemoveUser:
        if user_class < UserClass.Administrator:
            return bad_request_json("You do not have permission to do that.")
        try:
            user_id = request["user_id"]
        except KeyError:
            return bad_request_json("Must include a user id.")

        if type(user_id) is not int:
            return bad_request_json("user_id must be an int.")

        delete_user_command = """
            delete
            from users
            where id = ?
        """
        delete_user_params = (user_id,)
        sql_cur.execute(delete_user_command, delete_user_params)
        db.commit()
        return {
            "success": True,
            "data": None
        }

    # Admin: Score Order
    if request_type == ResourceRequestType.ChangeScoreOrder:
        try:
            leaderboard_id = request["leaderboard_id"]
            ascending = request["ascending"]
        except KeyError:
            return bad_request_json("Must include leaderboard id and ascending boolean.")

        if type(leaderboard_id) is not int:
            return bad_request_json("leaderboard_id must be an int.")
        if type(ascending) is not bool:
            return bad_request_json("ascending must be a bool.")

        update_order_command = """
            update leaderboards
            set ascending = ?
            where id = ?
        """
        update_order_params = (ascending, leaderboard_id)
        sql_cur.execute(update_order_command, update_order_params)
        db.commit()
        return {
            "success": True,
            "data": None
        }

    # Entry: Add Proof
    if request_type == ResourceRequestType.AddProof:
        try:
            entry_id = request["entry_id"]
            filename = request["filename"]
            file = base64.b64decode(request["file"])
        except KeyError:
            return bad_request_json("Must include entry id, a name for the file, and the file itself.")

        if type(entry_id) is not int:
            return bad_request_json("entry_id must be an int.")
        if type(filename) is not str:
            return bad_request_json("filename must be a string.")

        get_submitter_command = """
            select user
            from leaderboard_entries
            where id = ?
        """
        get_submitter_params = (entry_id,)
        sql_cur.execute(get_submitter_command, get_submitter_params)
        try:
            (submitter,) = sql_cur.fetchone()
        except TypeError:
            return bad_request_json("That entry does not exist.")

        if submitter != request_user_id:
            return bad_request_json("Can only add proof to your own entries.")

        add_file_command = """
            insert into files (entry, name, submission_date, data) values (?, ?, ?, ?)
        """
        add_file_params = (entry_id, filename, int(time.time()), file)
        sql_cur.execute(add_file_command, add_file_params)
        db.commit()
        return {
            "success": True,
            "data": None
        }

    # Entry: Download Proof
    if request_type == ResourceRequestType.DownloadProof:
        try:
            file_id = request["file_id"]
        except KeyError:
            return bad_request_json("Must include a file id.")

        if type(file_id) is not int:
            return bad_request_json("file_id must be an int.")

        # make sure the user should be able to see the associated entry
        get_leaderboard_command = """
            select e.user, e.verified, e.leaderboard
            from leaderboard_entries e
            where e.id in (select entry
                         from files
                         where id = ?)
        """
        get_leaderboard_params = (file_id,)
        sql_cur.execute(get_leaderboard_command, get_leaderboard_params)
        try:
            (submitter, verified, leaderboard_id) = sql_cur.fetchone()
        except TypeError:
            return bad_request_json("That entry does not exist.")
        (lb_id, lb_name, lb_perm, lb_asc) = get_leaderboard_info(request_user_id, leaderboard_id)
        if submitter == request_user_id or lb_perm >= Permissions.Moderate or (
                verified and lb_perm >= Permissions.Read):
            pass
        else:
            return bad_request_json("You do not have permission to do that.")

        get_file_command = """
            select data
            from files
            where id = ?
        """
        get_file_params = (file_id,)
        sql_cur.execute(get_file_command, get_file_params)
        try:
            (file,) = sql_cur.fetchone()
        except TypeError:
            return bad_request_json("That file does not exist.")
        return {
            "success": True,
            "data": base64.b64encode(file).decode()
        }

    if request_type == ResourceRequestType.ListAccessGroups:
        try:
            leaderboard_id = request["leaderboard_id"]
            (lb_id, lb_name, lb_perm, lb_asc) = get_leaderboard_info(request_user_id, leaderboard_id)
        except KeyError:
            return bad_request_json("Must include leaderboard id.")
        except TypeError:
            return bad_request_json("That leaderboard does not exist.")
        if type(leaderboard_id) is not int:
            return bad_request_json("leaderboard_id must be an int.")

        if lb_perm < Permissions.Moderate:
            return bad_request_json("You do not have permission to do that.")

        list_user_perms_command = """
            select u.id, u.identity, max(default_permission, class, coalesce(permission, 0)) as perm
            from users u
            left join (select * from permissions where leaderboard = ?) p
                on p.user = u.id
            left join (select default_permission from leaderboards where id = ?)
            order by perm
        """
        list_user_perms_params = (leaderboard_id, leaderboard_id)
        sql_cur.execute(list_user_perms_command, list_user_perms_params)
        user_list = sql_cur.fetchall()
        return {
            "success": True,
            "data": user_list
        }

    if request_type == ResourceRequestType.RemoveProof:
        try:
            file_id = request["file_id"]
        except KeyError:
            return bad_request_json("Must include file id.")

        if type(file_id) is not int:
            return bad_request_json("file_id must be an int.")

        get_submitter_command = """
            select e.user, leaderboard
            from files f
                left join leaderboard_entries e on f.entry = e.id
            where f.id = ?
        """
        get_submitter_params = (file_id,)
        sql_cur.execute(get_submitter_command, get_submitter_params)
        try:
            (submitter, leaderboard_id) = sql_cur.fetchone()
            (lb_id, lb_name, lb_perm, lb_asc) = get_leaderboard_info(request_user_id, leaderboard_id)
        except TypeError:
            return bad_request_json("That file does not exist.")

        if submitter != request_user_id and lb_perm < Permissions.Moderate:
            return bad_request_json("You do not have permission to do that.")

        remove_file_command = """
            delete
            from files
            where id = ?
        """
        remove_file_params = (file_id,)
        sql_cur.execute(remove_file_command, remove_file_params)
        db.commit()
        return {
            "success": True,
            "data": None
        }


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        print("Connection opened with {}".format(self.client_address[0]))
        # Initial connection
        request = src.netlib.get_dict_from_socket(self.request)
        if not request["type"] == ResourceRequestType.PublicKey:
            print("Initial request not for public key, exiting")
            return
        response = src.serverlib.public_key_response(public_key)
        src.netlib.send_dict_to_socket(response, self.request)

        # Authentication step
        request = src.netlib.get_dict_from_socket(self.request)
        if not request["type"] == ResourceRequestType.Authenticate:
            print("Secondary request not for authentication, exiting")
            return
        encrypted_key = src.netlib.b64_to_bytes(request["encrypted_key"])
        aes_key = src.cryptolib.rsa_decrypt(private_key, encrypted_key)
        signin_payload = src.netlib.b64_to_bytes(request["signin_payload"])
        signin_request = src.cryptolib.decrypt_dict(aes_key, signin_payload)
        socket_identity = signin_request["identity"]
        token = src.netlib.b64_to_bytes(signin_request["token"])
        if not src.cryptolib.rsa_verify_str(auth_public_key, token, socket_identity):
            print("Invalid login token, exiting")
            return
        nonce = os.urandom(32)
        encrypted_nonce = src.cryptolib.symmetric_encrypt(aes_key, nonce)
        response = {"nonce": src.netlib.bytes_to_b64(encrypted_nonce)}
        src.netlib.send_dict_to_socket(response, self.request)

        # verification
        if not request["type"] == ResourceRequestType.NonceReply:
            print("request type not a nonce reply, exiting")
            return
        request = src.netlib.get_dict_from_socket(self.request)
        reply_nonce = src.cryptolib.symmetric_decrypt(aes_key, request["nonce"])
        if not src.netlib.bytes_to_int(nonce) + 1 == src.netlib.bytes_to_int(reply_nonce):
            print("Invalid nonce reply, exiting")
            return
        encrypted_request = request["real_request"]
        further_request = src.cryptolib.decrypt_dict(aes_key, encrypted_request)
        response = handle_request(request)
        src.netlib.send_dict_to_socket(response, self.request)

        # TODO: make this loop use encrypted stuff
        while True:
            request = src.netlib.get_dict_from_socket(self.request)
            print("received {} from {}".format(request, self.client_address[0]))
            response = handle_request(request)
            print("sending {} to {}".format(response, self.client_address[0]))
            src.netlib.send_dict_to_socket(response, self.request)


def signal_handler(sig, frame):
    print("\nshutting down...")
    db.commit()
    server.server_close()
    sys.exit(0)


if __name__ == "__main__":
    db_schema = """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            identity TEXT UNIQUE NOT NULL,
            token TEXT NOT NULL,
            class INTEGER NOT NULL,
            registration_date INTEGER NOT NULL
        );
        CREATE TABLE leaderboards (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            creation_date INTEGER NOT NULL,
            default_permission INTEGER NOT NULL,
            ascending BOOLEAN NOT NULL
        );
        CREATE TABLE permissions (
            user INTEGER NOT NULL REFERENCES users(id),
            leaderboard INTEGER NOT NULL REFERENCES  leaderboards(id) ON DELETE CASCADE,
            permission INTEGER NOT NULL,
            change_date INTEGER NOT NULL
        );
        CREATE TABLE leaderboard_entries (
            id INTEGER PRIMARY KEY,
            user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            leaderboard INTEGER NOT NULL REFERENCES leaderboards(id) ON DELETE CASCADE,
            score REAL NOT NULL,
            submission_date INTEGER NOT NULL,
            verified INTEGER NOT NULL,
            verification_date INTEGER,
            verifier INTEGER REFERENCES users(id)
        );
        CREATE TABLE entry_comments (
            id INTEGER PRIMARY KEY,
            user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            entry INTEGER NOT NULL REFERENCES leaderboard_entries(id) ON DELETE CASCADE,
            date INTEGER NOT NULL,
            content TEXT NOT NULL
        );
        CREATE TABLE files (
            id INTEGER PRIMARY KEY,
            entry INTEGER NOT NULL REFERENCES leaderboard_entries(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            submission_date INTEGER NOT NULL,
            data BLOB NOT NULL
        );
    """

    # Filenames
    db_filename = "res_db"
    key_filename = "res_private_key"
    auth_public_key_filename = "auth_public_key"

    # Init Crypography stuff
    private_key = src.serverlib.initialize_key(key_filename)
    public_key = private_key.public_key()
    if not path.exists(auth_public_key_filename):
        print("No Auth server public key found! Please provide an authentication server public key.")
        sys.exit(1)
    with open(auth_public_key_filename, "rb") as key_file:
        auth_public_key: rsa.RSAPublicKey = serialization.load_ssh_public_key(key_file.read())
        print("Found Auth server public key.")
        print("Key Hash: " + src.cryptolib.public_key_hash(auth_public_key))

    # Init DB
    db = src.serverlib.initialize_database(db_filename, db_schema)

    # Init server
    HOST, PORT = "0.0.0.0", 8086
    signal.signal(signal.SIGINT, signal_handler)
    try:
        server = socketserver.ForkingTCPServer((HOST, PORT), Handler)
        print("socket bound successfully")
        server.serve_forever()
    except OSError:
        print("can't bind to " + HOST + ":" + str(PORT))
