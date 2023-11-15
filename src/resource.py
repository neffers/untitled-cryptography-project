import os
import socketserver
import sqlite3
import signal
import sys
from os import path
import time

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import serverlib
import cryptolib
import netlib
from enums import ResourceRequestType, Permissions, UserClass, ServerErrCode

TIMEOUT_SECONDS = 300


def get_leaderboard_perms(userid: int) -> dict:
    cur = db.cursor()
    get_perm_command = """
        select l.id, max(l.default_permission, coalesce(p.permission, 0), class) as perm
        from leaderboards l
            left join (select * from permissions where user = ?) p on l.id = p.leaderboard
            inner join (select class from users where id = ?)
    """
    get_perm_params = (userid, userid)
    cur.execute(get_perm_command, get_perm_params)
    perm_tuples = cur.fetchall()
    return {entry[0]: entry[1] for entry in perm_tuples}


def get_user_class(userid: int) -> UserClass:
    cur = db.cursor()
    get_class_command = "select class from users where id = ?"
    get_class_params = (userid,)
    cur.execute(get_class_command, get_class_params)
    (uc,) = cur.fetchone()
    return UserClass(uc)


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


def show_one_leaderboard_response(requesting_user_id: int, user_perms: dict, leaderboard_id: int):
    cursor = db.cursor()
    # make sure leaderboard should be visible by user
    try:
        permission = user_perms[leaderboard_id]
    except KeyError:
        return serverlib.bad_request_json(ServerErrCode.DoesNotExist)
    if permission < Permissions.Read:
        return serverlib.bad_request_json(ServerErrCode.InsufficientPermission)
    # Get leaderboard name and ascending
    leaderboard_info_command = "select name, ascending from leaderboards where id = ?"
    leaderboard_info_params = (leaderboard_id,)
    cursor.execute(leaderboard_info_command, leaderboard_info_params)
    (leaderboard_name, ascending) = cursor.fetchone()
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


def add_leaderboard(new_lb_name: str, new_lb_perm: Permissions, new_lb_asc: bool) -> dict:
    cur = db.cursor()
    new_lb_command = """
        insert into leaderboards(name, creation_date, default_permission, ascending) values(?, strftime('%s'), ?, ?)
    """
    new_lb_params = (new_lb_name, new_lb_perm, new_lb_asc)
    cur.execute(new_lb_command, new_lb_params)
    db.commit()
    new_lb_id = cur.lastrowid
    return {
        "success": True,
        "data": new_lb_id,
    }


def add_entry(requesting_user_id: int, user_perms: dict, leaderboard_id: int, entry_score: float, comment: str) -> dict:
    # error if leaderboard id doesn't exist
    try:
        lb_perm = user_perms[leaderboard_id]
    except KeyError:
        return serverlib.bad_request_json(ServerErrCode.DoesNotExist)
    # error if you don't have permission to write to it
    if lb_perm < Permissions.Write:
        return serverlib.bad_request_json(ServerErrCode.InsufficientPermission)
    create_entry_command = """
        insert into leaderboard_entries(user, leaderboard, score, submission_date, verified)
        values(?, ?, ?, strftime('%s'), ?)
    """
    create_entry_params = (requesting_user_id, leaderboard_id, entry_score, False)
    cur = db.cursor()
    cur.execute(create_entry_command, create_entry_params)
    entry_id = cur.lastrowid
    create_comment_command = """
        insert into entry_comments(user, entry, date, content)
        values(?, ?, strftime('%s'), ?)
    """
    create_comment_params = (requesting_user_id, entry_id, comment)
    cur.execute(create_comment_command, create_comment_params)
    db.commit()
    return {
        "success": True,
        "data": entry_id,
    }


def list_users() -> dict:
    cur = db.cursor()
    get_users_command = """
        select id, identity
            from users
        order by id
    """
    cur.execute(get_users_command)
    users = cur.fetchall()
    return {
        "success": True,
        "data": users,
    }


def list_unverified(requesting_user_id: int, leaderboard_id: int) -> dict:
    cursor = db.cursor()
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
    list_unverified_params = (requesting_user_id, requesting_user_id, requesting_user_id, leaderboard_id)
    cursor.execute(list_unverified_command, list_unverified_params)

    entries = cursor.fetchall()
    return {
        "success": True,
        "data": entries,
    }


def get_entry(requesting_user_id: int, user_perms: dict, entry_id: int) -> dict:
    cursor = db.cursor()
    # Check permissions by first getting leaderboard id and then getting requesting user's perms for it
    get_leaderboard_id_command = """
        select user, leaderboard, verified
        from leaderboard_entries
        where id = ?
    """
    get_leaderboard_id_params = (entry_id,)
    cursor.execute(get_leaderboard_id_command, get_leaderboard_id_params)
    try:
        (submitter, leaderboard_id, verified) = cursor.fetchone()
    except TypeError:
        return serverlib.bad_request_json(ServerErrCode.DoesNotExist)
    lb_perm = user_perms[leaderboard_id]
    if (verified and lb_perm >= Permissions.Read) or (
            not verified and (submitter == requesting_user_id or lb_perm >= Permissions.Moderate)):
        pass
    else:
        return serverlib.bad_request_json(ServerErrCode.InsufficientPermission)

    get_entry_command = """
        select e.id, user, u.identity, score, submission_date, verified, verifier, v.identity, verification_date
        from leaderboard_entries e
        left join main.users u on e.user = u.id
        left join main.users v on e.verifier = v.id
        where e.id = ?
    """
    get_entry_params = (entry_id,)
    cursor.execute(get_entry_command, get_entry_params)
    entry = cursor.fetchone()

    get_comments_command = """
        select u.identity, date, content
        from entry_comments c
        left join main.users u on u.id = c.user
        where c.entry = ?
        order by date
    """
    get_comments_params = (entry_id,)
    cursor.execute(get_comments_command, get_comments_params)
    comments = cursor.fetchall()

    get_files_command = """
        select id, name, submission_date
        from files
        where entry = ?
    """
    get_files_params = (entry_id,)
    cursor.execute(get_files_command, get_files_params)
    files = cursor.fetchall()

    data_to_return = {
        "entry": entry,
        "comments": comments,
        "files": files,
    }
    return {
        "success": True,
        "data": data_to_return,
    }


def get_user(requesting_user_id: int, user_id: int) -> dict:
    cursor = db.cursor()
    get_user_command = """
        select identity, registration_date
            from users
        where id = ?
    """
    get_user_params = (user_id,)
    cursor.execute(get_user_command, get_user_params)
    user_data = cursor.fetchone()
    if user_data is None:
        return serverlib.bad_request_json(ServerErrCode.DoesNotExist)

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
    get_entries_params = (requesting_user_id, requesting_user_id, Permissions.Moderate, requesting_user_id, user_id)
    cursor.execute(get_entries_command, get_entries_params)
    entries = cursor.fetchall()

    data_to_return = {
        "user_data": user_data,
        "entries": entries,
    }
    return {
        "success": True,
        "data": data_to_return,
    }


def modify_verification(request_user_id: int, user_perms: dict, entry_id: int, verified: bool) -> dict:
    cur = db.cursor()
    get_entry_command = "select leaderboard from leaderboard_entries where id = ?"
    get_entry_params = (entry_id,)
    cur.execute(get_entry_command, get_entry_params)
    try:
        (leaderboard_id,) = cur.fetchone()
    except TypeError:
        return serverlib.bad_request_json(ServerErrCode.DoesNotExist)

    lb_perm = user_perms[leaderboard_id]
    if lb_perm < Permissions.Moderate:
        return serverlib.bad_request_json(ServerErrCode.InsufficientPermission)

    modify_entry_command = """
        update leaderboard_entries
        set verified = ?, verifier = ?, verification_date = strftime('%s')
        where id = ?
    """
    modify_entry_params = (verified, request_user_id, entry_id)
    cur.execute(modify_entry_command, modify_entry_params)
    db.commit()
    return {
        "success": True,
        "data": None,
    }


def add_comment(request_user_id: int, user_perms: dict, entry_id: int, content: str) -> dict:
    cur = db.cursor()
    # Check permissions by first getting leaderboard id and then getting requesting user's perms for it
    get_leaderboard_id_command = """
        select user, leaderboard
        from leaderboard_entries
        where id = ?
    """
    get_leaderboard_id_params = (entry_id,)
    cur.execute(get_leaderboard_id_command, get_leaderboard_id_params)
    try:
        (submitter, leaderboard_id) = cur.fetchone()
    except TypeError:
        return serverlib.bad_request_json(ServerErrCode.DoesNotExist)
    lb_perm = user_perms[leaderboard_id]
    if not (request_user_id == submitter or lb_perm >= Permissions.Moderate):
        return serverlib.bad_request_json(ServerErrCode.InsufficientPermission)

    add_comment_command = """
        insert into entry_comments(user, entry, date, content)
            values (?, ?, strftime('%s'), ?)
    """
    add_comment_params = (request_user_id, entry_id, content)
    cur.execute(add_comment_command, add_comment_params)
    db.commit()
    return {
        "success": True,
        "data": None,
    }


def remove_leaderboard(leaderboard_id: int) -> dict:
    cur = db.cursor()
    remove_leaderboard_command = "delete from leaderboards where id = ?"
    remove_leaderboard_params = (leaderboard_id,)
    cur.execute(remove_leaderboard_command, remove_leaderboard_params)
    db.commit()
    return {
        "success": True,
        "data": None
    }


def remove_entry(request_user_id: int, user_class: UserClass, entry_id: int) -> dict:
    cur = db.cursor()
    get_submitter_command = """
        select user
        from leaderboard_entries
        where id = ?
    """
    get_submitter_params = (entry_id,)
    cur.execute(get_submitter_command, get_submitter_params)
    (submitter,) = cur.fetchone()

    if user_class < UserClass.Administrator and submitter != request_user_id:
        return serverlib.bad_request_json(ServerErrCode.InsufficientPermission)

    remove_entry_command = "delete from leaderboard_entries where id = ?"
    cur.execute(remove_entry_command, (entry_id,))
    db.commit()
    return {
        "success": True,
        "data": None
    }


def view_permissions(user_id: int) -> dict:
    cur = db.cursor()
    view_permissions_command = "SELECT leaderboard, permission FROM permissions WHERE user = ?"
    cur.execute(view_permissions_command, (user_id,))
    permissions = cur.fetchall()
    return {
        "success": True,
        "data": permissions,
    }


def set_permission(user_id: int, leaderboard_id: int, p: Permissions) -> dict:
    cur = db.cursor()
    delete_old_permissions_command = """
        delete
        from permissions
        where user = ? and leaderboard = ?
    """
    delete_old_permissions_params = (user_id, leaderboard_id)
    cur.execute(delete_old_permissions_command, delete_old_permissions_params)

    set_permission_command = """
        insert
        into permissions (user, leaderboard, permission, change_date)
        values (?, ?, ?, strftime('%s'))
    """
    set_permission_params = (user_id, leaderboard_id, p)
    try:
        cur.execute(set_permission_command, set_permission_params)
    except sqlite3.IntegrityError:
        return serverlib.bad_request_json(ServerErrCode.DoesNotExist)
    db.commit()
    return {
        "success": True,
        "data": None
    }


def remove_user(user_id: int) -> dict:
    cur = db.cursor()
    delete_user_command = """
        delete
        from users
        where id = ?
    """
    delete_user_params = (user_id,)
    cur.execute(delete_user_command, delete_user_params)
    db.commit()
    return {
        "success": True,
        "data": None
    }


def set_score_order(leaderboard_id: int, ascending: bool) -> dict:
    cur = db.cursor()
    update_order_command = """
        update leaderboards
        set ascending = ?
        where id = ?
    """
    update_order_params = (ascending, leaderboard_id)
    cur.execute(update_order_command, update_order_params)
    db.commit()
    return {
        "success": True,
        "data": None
    }


def add_proof(request_user_id: int, entry_id: int, filename: str, file: bytes) -> dict:
    cur = db.cursor()
    get_submitter_command = """
        select user
        from leaderboard_entries
        where id = ?
    """
    get_submitter_params = (entry_id,)
    cur.execute(get_submitter_command, get_submitter_params)
    try:
        (submitter,) = cur.fetchone()
    except TypeError:
        return serverlib.bad_request_json(ServerErrCode.DoesNotExist)

    if submitter != request_user_id:
        return serverlib.bad_request_json(ServerErrCode.InsufficientPermission)

    add_file_command = """
        insert into files (entry, name, submission_date, data) values (?, ?, strftime('%s'), ?)
    """
    add_file_params = (entry_id, filename, file)
    cur.execute(add_file_command, add_file_params)
    db.commit()
    return {
        "success": True,
        "data": None
    }


def download_proof(request_user_id: int, user_perms: dict, file_id: int) -> dict:
    cur = db.cursor()
    # make sure the user should be able to see the associated entry
    get_leaderboard_command = """
        select e.user, e.verified, e.leaderboard
        from leaderboard_entries e
        where e.id in (select entry
                     from files
                     where id = ?)
    """
    get_leaderboard_params = (file_id,)
    cur.execute(get_leaderboard_command, get_leaderboard_params)
    try:
        (submitter, verified, leaderboard_id) = cur.fetchone()
    except TypeError:
        return serverlib.bad_request_json(ServerErrCode.DoesNotExist)
    lb_perm = user_perms[leaderboard_id]
    if submitter == request_user_id or lb_perm >= Permissions.Moderate or (
            verified and lb_perm >= Permissions.Read):
        pass
    else:
        return serverlib.bad_request_json(ServerErrCode.InsufficientPermission)

    get_file_command = """
        select data
        from files
        where id = ?
    """
    get_file_params = (file_id,)
    cur.execute(get_file_command, get_file_params)
    (file,) = cur.fetchone()
    return {
        "success": True,
        "data": netlib.bytes_to_b64(file)
    }


def list_access_groups(leaderboard_id: int) -> dict:
    cur = db.cursor()
    list_user_perms_command = """
        select u.id, u.identity, max(default_permission, class, coalesce(permission, 0)) as perm
        from users u
        left join (select * from permissions where leaderboard = ?) p
            on p.user = u.id
        left join (select default_permission from leaderboards where id = ?)
        order by perm
    """
    list_user_perms_params = (leaderboard_id, leaderboard_id)
    cur.execute(list_user_perms_command, list_user_perms_params)
    user_list = cur.fetchall()
    return {
        "success": True,
        "data": user_list
    }


def remove_proof(request_user_id: int, user_perms: dict, file_id: int) -> dict:
    cur = db.cursor()
    get_submitter_command = """
        select e.user, leaderboard
        from files f
            left join leaderboard_entries e on f.entry = e.id
        where f.id = ?
    """
    get_submitter_params = (file_id,)
    cur.execute(get_submitter_command, get_submitter_params)
    try:
        (submitter, leaderboard_id) = cur.fetchone()
    except TypeError:
        return serverlib.bad_request_json(ServerErrCode.DoesNotExist)
    lb_perm = user_perms[leaderboard_id]

    if submitter != request_user_id and lb_perm < Permissions.Moderate:
        return serverlib.bad_request_json(ServerErrCode.InsufficientPermission)

    remove_file_command = """
        delete
        from files
        where id = ?
    """
    remove_file_params = (file_id,)
    cur.execute(remove_file_command, remove_file_params)
    db.commit()
    return {
        "success": True,
        "data": None
    }


def handle_request(request_user_id: int, request: dict):
    perms = get_leaderboard_perms(request_user_id)
    user_class = get_user_class(request_user_id)
    # Every request needs to have these
    try:
        request_type = request["type"]
        if not isinstance(request_type, int):
            raise TypeError
    except KeyError or TypeError:
        return serverlib.bad_request_json(ServerErrCode.MalformedRequest)

    # Get public key
    if request_type == ResourceRequestType.PublicKey:
        return serverlib.public_key_response(public_key)

    # Basic: List Leaderboards
    if request_type == ResourceRequestType.ListLeaderboards:
        return list_leaderboards_response(request_user_id)

    # Basic: Open Leaderboard
    # Leaderboard: List Entries
    if request_type == ResourceRequestType.ShowOneLeaderboard:
        try:
            leaderboard_id = request["leaderboard_id"]
            if not isinstance(leaderboard_id, int):
                raise TypeError
        except KeyError or TypeError:
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return show_one_leaderboard_response(request_user_id, perms, leaderboard_id)

    # Basic: Add Leaderboard
    if request_type == ResourceRequestType.CreateLeaderboard:
        if user_class != UserClass.Administrator:
            return serverlib.bad_request_json(ServerErrCode.InsufficientPermission)
        try:
            new_lb_name = request["leaderboard_name"]
            if not isinstance(new_lb_name, str):
                raise TypeError
            new_lb_perm = request["leaderboard_permission"]
            if not isinstance(new_lb_perm, int):
                raise TypeError
            new_lb_perm = Permissions(new_lb_perm)
            new_lb_asc = request["leaderboard_ascending"]
            if not isinstance(new_lb_asc, bool):
                raise TypeError
        except KeyError or TypeError or ValueError:
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return add_leaderboard(new_lb_name, new_lb_perm, new_lb_asc)

    # Leaderboard: Submit Entry
    if request_type == ResourceRequestType.AddEntry:
        try:
            leaderboard_id = request["leaderboard_id"]
            if not isinstance(leaderboard_id, int):
                raise TypeError
            entry_score = request["score"]
            if not isinstance(entry_score, (float, int)):
                raise TypeError
            comment = request["comment"]
            if not isinstance(comment, str):
                raise TypeError
        except KeyError or TypeError:
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)

        return add_entry(request_user_id, perms, leaderboard_id, entry_score, comment)

    # Basic: List Users
    if request_type == ResourceRequestType.ListUsers:
        return list_users()

    # Leaderboard: List Unverified
    if request_type == ResourceRequestType.ListUnverified:
        try:
            leaderboard_id = request["leaderboard_id"]
            if not isinstance(leaderboard_id, int):
                raise TypeError
        except KeyError or TypeError:
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return list_unverified(request_user_id, leaderboard_id)

    # Leaderboard: Open Entry
    # Entry: View Entry
    # Entry: View Comments
    # User: Open Submission
    if request_type == ResourceRequestType.GetEntry:
        try:
            entry_id = request["entry_id"]
            if not isinstance(entry_id, int):
                raise TypeError
        except KeyError or TypeError:
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return get_entry(request_user_id, perms, entry_id)

    # User: View User (get visible entries)
    # Basic: Open user
    # Basic: open self
    if request_type == ResourceRequestType.ViewUser:
        try:
            user_id = request["user_id"]
            if not isinstance(user_id, int):
                raise TypeError
        except KeyError or TypeError:
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return get_user(request_user_id, user_id)

    # Internal
    if request_type == ResourceRequestType.GetSelfID:
        return {
            "success": True,
            "data": request_user_id
        }

    # Entry: Verify Entry
    # Entry: Un-verify Entry
    if request_type == ResourceRequestType.ModifyEntryVerification:
        try:
            entry_id = request["entry_id"]
            if not isinstance(entry_id, int):
                raise TypeError
            verified = request["verified"]
            if not isinstance(verified, bool):
                raise TypeError
        except KeyError or TypeError:
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return modify_verification(request_user_id, perms, entry_id, verified)

    # Entry: Add comment
    if request_type == ResourceRequestType.AddComment:
        try:
            entry_id = request["entry_id"]
            if not isinstance(entry_id, int):
                raise TypeError
            content = request["content"]
            if not isinstance(content, str):
                raise TypeError
        except KeyError or TypeError:
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return add_comment(request_user_id, perms, entry_id, content)

    # Admin: Remove Leaderboard
    if request_type == ResourceRequestType.RemoveLeaderboard:
        if user_class != UserClass.Administrator:
            return serverlib.bad_request_json(ServerErrCode.InsufficientPermission)
        try:
            leaderboard_id = request["leaderboard_id"]
            if not isinstance(leaderboard_id, int):
                raise TypeError
        except KeyError or TypeError:
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return remove_leaderboard(leaderboard_id)

    # Entry: Remove Entry
    if request_type == ResourceRequestType.RemoveEntry:
        try:
            entry_id = request["entry_id"]
            if not isinstance(entry_id, int):
                raise TypeError
        except KeyError or TypeError:
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return remove_entry(request_user_id, user_class, entry_id)

    # User: View Permissions
    if request_type == ResourceRequestType.ViewPermissions:
        if user_class < UserClass.Administrator:
            return serverlib.bad_request_json(ServerErrCode.InsufficientPermission)
        try:
            user_id = request["user_id"]
            if not isinstance(user_id, int):
                raise TypeError
        except KeyError or TypeError:
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return view_permissions(user_id)

    # User: Set Permission
    if request_type == ResourceRequestType.SetPermission:
        if user_class < UserClass.Administrator:
            return serverlib.bad_request_json(ServerErrCode.InsufficientPermission)
        try:
            user_id = request["user_id"]
            if not isinstance(user_id, int):
                raise TypeError
            leaderboard_id = request["leaderboard_id"]
            if not isinstance(leaderboard_id, int):
                raise TypeError
            p = request["permission"]
            if not isinstance(p, int):
                raise TypeError
            p = Permissions(request["permission"])
        except KeyError or TypeError or ValueError:
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return set_permission(user_id, leaderboard_id, p)

    # User: Remove User
    if request_type == ResourceRequestType.RemoveUser:
        if user_class < UserClass.Administrator:
            return serverlib.bad_request_json(ServerErrCode.InsufficientPermission)
        try:
            user_id = request["user_id"]
            if not isinstance(user_id, int):
                raise TypeError
        except KeyError or TypeError:
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return remove_user(user_id)

    # Admin: Score Order
    if request_type == ResourceRequestType.ChangeScoreOrder:
        try:
            leaderboard_id = request["leaderboard_id"]
            if not isinstance(leaderboard_id, int):
                raise TypeError
            ascending = request["ascending"]
            if not isinstance(ascending, bool):
                raise TypeError
        except KeyError or TypeError:
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return set_score_order(leaderboard_id, ascending)

    # Entry: Add Proof
    if request_type == ResourceRequestType.AddProof:
        try:
            entry_id = request["entry_id"]
            if not isinstance(entry_id, int):
                raise TypeError
            filename = request["filename"]
            if not isinstance(filename, str):
                raise TypeError
            file = netlib.b64_to_bytes(request["file"])
        except KeyError or TypeError:
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return add_proof(request_user_id, entry_id, filename, file)

    # Entry: Download Proof
    if request_type == ResourceRequestType.DownloadProof:
        try:
            file_id = request["file_id"]
            if not isinstance(file_id, int):
                raise TypeError
        except KeyError or TypeError:
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return download_proof(request_user_id, perms, file_id)

    if request_type == ResourceRequestType.ListAccessGroups:
        try:
            leaderboard_id = request["leaderboard_id"]
            if not isinstance(leaderboard_id, int):
                raise TypeError
        except KeyError or TypeError:
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        try:
            lb_perm = perms[leaderboard_id]
        except KeyError:
            return serverlib.bad_request_json(ServerErrCode.DoesNotExist)

        if lb_perm < Permissions.Moderate:
            return serverlib.bad_request_json(ServerErrCode.InsufficientPermission)
        return list_access_groups(leaderboard_id)

    if request_type == ResourceRequestType.RemoveProof:
        try:
            file_id = request["file_id"]
            if not isinstance(file_id, int):
                raise TypeError
        except KeyError or TypeError:
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return remove_proof(request_user_id, perms, file_id)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        print("Connection opened with {}".format(self.client_address[0]))
        # Initial connection
        request = netlib.get_dict_from_socket(self.request)
        if not request["type"] == ResourceRequestType.PublicKey:
            print("Initial request not for public key, exiting")
            netlib.send_dict_to_socket(serverlib.bad_request_json(ServerErrCode.MalformedRequest), self.request)
            return
        response = serverlib.public_key_response(public_key)
        netlib.send_dict_to_socket(response, self.request)

        # Authentication step
        request = netlib.get_dict_from_socket(self.request)
        if not request["type"] == ResourceRequestType.Authenticate:
            print("Secondary request not for authentication, exiting")
            netlib.send_dict_to_socket(serverlib.bad_request_json(ServerErrCode.MalformedRequest), self.request)
            return
        encrypted_key = netlib.b64_to_bytes(request["encrypted_key"])
        aes_key = cryptolib.rsa_decrypt(private_key, encrypted_key)
        signin_payload = netlib.b64_to_bytes(request["signin_payload"])
        signin_request = cryptolib.decrypt_dict(aes_key, signin_payload)
        socket_identity = signin_request["identity"]
        token = netlib.b64_to_bytes(signin_request["token"])
        if not cryptolib.rsa_verify_str(auth_public_key, token, socket_identity):
            print("Invalid login token, exiting")
            netlib.send_dict_to_socket(serverlib.bad_request_json(ServerErrCode.AuthenticationFailure), self.request)
            return
        nonce = os.urandom(32)
        encrypted_nonce = cryptolib.symmetric_encrypt(aes_key, nonce)
        response = {"nonce": netlib.bytes_to_b64(encrypted_nonce)}
        netlib.send_dict_to_socket(response, self.request)

        # verification
        if not request["type"] == ResourceRequestType.NonceReply:
            print("request type not a nonce reply, exiting")
            netlib.send_dict_to_socket(serverlib.bad_request_json(ServerErrCode.MalformedRequest), self.request)
            return
        request = netlib.get_dict_from_socket(self.request)
        reply_nonce = cryptolib.symmetric_decrypt(aes_key, request["nonce"])
        if not netlib.bytes_to_int(nonce) + 1 == netlib.bytes_to_int(reply_nonce):
            print("Invalid nonce reply, exiting")
            netlib.send_dict_to_socket(serverlib.bad_request_json(ServerErrCode.AuthenticationFailure), self.request)
            return

        # verified
        last_request_time = int(time.time())
        # Register user if not registered
        print("User {} successfully connected".format(socket_identity))
        cursor = db.cursor()
        register_command = """
            insert into users(identity, class, registration_date) values(?, ?, strftime('%s'))
            on conflict do nothing
            """
        register_params = (socket_identity, UserClass.User)
        cursor.execute(register_command, register_params)
        db.commit()

        # add admin if none exist
        get_admins_command = "select * from users where class = ?"
        get_admins_params = (UserClass.Administrator,)
        cursor.execute(get_admins_command, get_admins_params)
        admins = cursor.fetchall()
        if len(admins) == 0:
            print("No admins found, setting {} as admin.".format(socket_identity))
            add_admin_command = "update users set class = ? where identity = ?"
            add_admin_params = (UserClass.Administrator, socket_identity)
            cursor.execute(add_admin_command, add_admin_params)
            db.commit()

        # Get requesting user ID
        get_id_command = "select id from users where identity = ?"
        get_id_params = (socket_identity,)
        cursor.execute(get_id_command, get_id_params)
        (socket_user_id,) = cursor.fetchone()

        encrypted_request = request["encrypted_request"]
        further_request = cryptolib.decrypt_dict(aes_key, encrypted_request)
        response = handle_request(socket_user_id, further_request)
        netlib.send_dict_to_socket(response, self.request)

        # TODO: make this loop use encrypted stuff
        # TODO: change docs to not require identity/token on requests
        # TODO: Handle disconnect
        while True:
            request = netlib.get_dict_from_socket(self.request)
            if last_request_time + TIMEOUT_SECONDS > int(time.time()):
                print("Received request on timed out session, exiting.")
                netlib.send_dict_to_socket(serverlib.bad_request_json(ServerErrCode.SessionExpired), self.request)
                return
            else:
                last_request_time = int(time.time())
            print("received {} from {}".format(request, self.client_address[0]))
            response = handle_request(socket_user_id, request)
            print("sending {} to {}".format(response, self.client_address[0]))
            netlib.send_dict_to_socket(response, self.request)


# noinspection PyUnusedLocal
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

    # Init Cryptography stuff
    private_key = serverlib.initialize_key(key_filename)
    public_key = private_key.public_key()
    if not path.exists(auth_public_key_filename):
        print("No Auth server public key found! Please provide an authentication server public key.")
        sys.exit(1)
    with open(auth_public_key_filename, "rb") as key_file:
        auth_public_key: rsa.RSAPublicKey = serialization.load_ssh_public_key(key_file.read())
        print("Found Auth server public key.")
        print("Key Hash: " + cryptolib.public_key_hash(auth_public_key))

    # Init DB
    db = serverlib.initialize_database(db_filename, db_schema)

    # Init server
    HOST, PORT = "0.0.0.0", 8086
    signal.signal(signal.SIGINT, signal_handler)
    try:
        server = socketserver.ForkingTCPServer((HOST, PORT), Handler)
        print("socket bound successfully")
        server.serve_forever()
    except OSError:
        print("can't bind to " + HOST + ":" + str(PORT))
