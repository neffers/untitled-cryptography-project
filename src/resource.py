import os
import socket
import socketserver
import sqlite3
import signal
import sys
import time
from os import path
from typing import Union

from cryptography.hazmat.primitives.asymmetric import rsa

import serverlib
import cryptolib
import netlib
from enums import ResourceRequestType, Permissions, UserClass, ServerErrCode


def get_leaderboard_perms(userid: int) -> dict:
    cur = db.cursor()
    get_perm_command = """
        select l.id, coalesce(p.permission, 0) as perm
        from leaderboards l
            left join (select * from permissions where user = ?) p on l.id = p.leaderboard
    """
    get_perm_params = (userid,)
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
        select l.id, l.name, coalesce(p.permission, 0) as perm
        from leaderboards l
            left join (select * from permissions where user = ?) p on l.id = p.leaderboard
        where perm >= ?
    """
    get_leaderboards_params = (requesting_user_id, Permissions.Read)
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
            select e.id, user, u.identity, score, submission_date, verified, read_key_ver, mod_key, mod_key_ver
                from leaderboard_entries e
                join main.leaderboards l on e.leaderboard = l.id
                join main.users u on e.user = u.id
            where l.id = ?
        """
        get_entries_params = (leaderboard_id,)
    else:
        # Non-mods get visible entries and those that they submitted
        get_entries_command = """
            select e.id, user, u.identity, score, submission_date, verified, read_key_ver, uploader_key
                from leaderboard_entries e
                join main.leaderboards l on e.leaderboard = l.id
                join main.users u on e.user = u.id
            where (verified or user = ?) and l.id = ?
        """
        get_entries_params = (requesting_user_id, leaderboard_id)

    cursor.execute(get_entries_command, get_entries_params)
    entries = cursor.fetchall()
    data_to_return = {
        "id": leaderboard_id,
        "name": leaderboard_name,
        "ascending": ascending,
        "entries": entries
    }
    return {
        "success": True,
        "data": data_to_return,
    }


def add_leaderboard(creator_id: int, new_lb_name: str, new_lb_asc: bool, mod_pubkey: bytes, creator_read_key: bytes,
                    creator_mod_sym: bytes, creator_mod_priv: bytes) -> dict:
    cur = db.cursor()
    new_lb_command = """
        insert into leaderboards(name, creation_date, ascending, mod_pubkey, read_key_version, mod_key_version)
        values(?, strftime('%s'), ?, ?, ?, ?)
    """
    new_lb_params = (new_lb_name, new_lb_asc, mod_pubkey, 1, 1)
    cur.execute(new_lb_command, new_lb_params)
    leaderboard_id = cur.lastrowid

    create_perm_command = """
    insert into permissions(user, leaderboard, permission, change_date)
    values(?, ?, ?, strftime('%s'))
    """
    create_perm_params = (creator_id, leaderboard_id, Permissions.Moderate)
    cur.execute(create_perm_command, create_perm_params)
    perm_id = cur.lastrowid

    add_read_key_command = """
    insert into read_keys(associated_perm, version, encrypted_key)
    values(?, ?, ?)
    """
    add_read_key_params = (perm_id, 1, creator_read_key)
    cur.execute(add_read_key_command, add_read_key_params)

    add_mod_key_command = """
    insert into mod_keys(associated_perm, version, encrypted_sym_key, encrypted_priv_key)
    values(?, ?, ?, ?)
    """
    add_mod_key_params = (perm_id, 1, creator_mod_sym, creator_mod_priv)
    cur.execute(add_mod_key_command, add_mod_key_params)

    db.commit()
    return {
        "success": True,
        "data": leaderboard_id,
    }


def add_entry(requesting_user_id: int, user_perms: dict, leaderboard_id: int, entry_score: bytes, comment: bytes,
              uploader_key: bytes, mod_key: bytes, mod_key_ver: int) -> dict:
    # error if leaderboard id doesn't exist
    try:
        lb_perm = user_perms[leaderboard_id]
    except KeyError:
        return serverlib.bad_request_json(ServerErrCode.DoesNotExist)
    # error if you don't have permission to write to it
    if lb_perm < Permissions.Write:
        return serverlib.bad_request_json(ServerErrCode.InsufficientPermission)
    create_entry_command = """
    insert into leaderboard_entries(user, leaderboard, score, submission_date, verified, uploader_key, mod_key, mod_key_ver)
    values(?, ?, ?, strftime('%s'), ?, ?, ?, ?)
    """
    create_entry_params = (requesting_user_id, leaderboard_id, entry_score, False, uploader_key, mod_key, mod_key_ver)
    cur = db.cursor()
    cur.execute(create_entry_command, create_entry_params)
    entry_id = cur.lastrowid
    create_comment_command = """
    insert into entry_comments(user, entry, date, content, uploader_key, mod_key, mod_key_ver)
    values(?, ?, strftime('%s'), ?)
    """
    create_comment_params = (requesting_user_id, entry_id, comment, uploader_key, mod_key, mod_key_ver)
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
        select e.id, user, identity, submission_date
        from leaderboard_entries e
                 left outer join leaderboards l on e.leaderboard = l.id
                 left outer join (select p.permission, p.leaderboard
                                  from users u
                                           left join permissions p on p.user = u.id
                                  where u.id = ?) x
                                 on e.leaderboard = x.leaderboard
        where (user = ? or coalesce(permission, 0) >= 3) and not verified
          and e.leaderboard = ?
    """
    list_unverified_params = (requesting_user_id, requesting_user_id, leaderboard_id)
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
        select e.id, user, u.identity, score, submission_date, uploader_key, mod_key, mod_key_ver, read_key_ver, verified, verifier, v.identity, verification_date
        from leaderboard_entries e
        left join main.users u on e.user = u.id
        left join main.users v on e.verifier = v.id
        where e.id = ?
    """
    get_entry_params = (entry_id,)
    cursor.execute(get_entry_command, get_entry_params)
    entry = cursor.fetchone()

    get_comments_command = """
        select u.identity, date, content, uploader_key, mod_key, mod_key_ver, read_key_ver
        from entry_comments c
        left join main.users u on u.id = c.user
        where c.entry = ?
        order by date
    """
    get_comments_params = (entry_id,)
    cursor.execute(get_comments_command, get_comments_params)
    comments = cursor.fetchall()

    get_files_command = """
        select id, name, submission_date, uploader_key, mod_key, mod_key_ver, read_key_ver
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
        left outer join (select p.permission, p.leaderboard
                         from users u
                         left join permissions p on p.user = u.id
                         where u.id = ?) x
            on e.leaderboard = x.leaderboard
        where (verified or (coalesce(permission, 0) >= ?) or e.user = ?)
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


def verify_entry(request_user_id: int, user_perms: dict, entry_id: int,
                 score: bytes, read_key_ver: int, comments: dict, files: dict) -> dict:
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
        set score = ?, verified = ?, verifier = ?, verification_date = strftime('%s'), uploader_key = ?, mod_key = ?,
        mod_key_ver = ?, read_key_ver = ?
        where id = ?
    """
    modify_entry_params = (score, True, request_user_id, entry_id, None, None, None, read_key_ver)
    cur.execute(modify_entry_command, modify_entry_params)

    modify_comment_command = """
    update entry_comments
    set content = ?, uploader_key = ?, mod_key = ?, mod_key_ver = ?, read_key_ver = ?
    where id = ?
    """
    for comment_id in comments:
        modify_comment_params = (comments[comment_id], None, None, None, read_key_ver, comment_id)
        cur.execute(modify_comment_command, modify_comment_params)

    modify_file_command = """
    update files
    set data = ?, uploader_key = ?, mod_key = ?, mod_key_ver = ?, read_key_ver = ?
    where id = ?
    """
    for file_id in files:
        modify_file_params = (files[file_id], None, None, None, read_key_ver, file_id)
        cur.execute(modify_file_command, modify_file_params)

    db.commit()
    return {
        "success": True,
        "data": None,
    }


def add_comment(request_user_id: int, user_perms: dict, entry_id: int, content: bytes,
                uploader_key: bytes, mod_key: bytes, mod_key_ver: int) -> dict:
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
    insert into entry_comments(user, entry, date, content, uploader_key, mod_key, mod_key_ver)
        values (?, ?, strftime('%s'), ?, ?, ?, ?)
    """
    add_comment_params = (request_user_id, entry_id, content, uploader_key, mod_key, mod_key_ver)
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


def add_permission(user_id: int, leaderboard_id: int, p: Permissions, read_keys: list, mod_keys: Union[list, None]) -> dict:
    cur = db.cursor()
    get_old_permissions_command = """
        select *
        from permissions
        where user = ? and leaderboard = ?
    """
    get_old_permissions_params = (user_id, leaderboard_id)
    cur.execute(get_old_permissions_command, get_old_permissions_params)
    if cur.fetchone() is not None:
        return serverlib.bad_request_json(ServerErrCode.MalformedRequest, "Already exists")

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
    perm_id = cur.lastrowid

    add_read_keys_command = """
    insert into read_keys(associated_perm, version, encrypted_key)
    values(?, ?, ?)
    """
    for i in range(len(read_keys)):
        read_key = netlib.b64_to_bytes(read_keys[i])
        add_read_keys_params = (perm_id, i, read_key)
        cur.execute(add_read_keys_command, add_read_keys_params)

    if mod_keys is not None:
        add_mod_keys_command = """
        insert into mod_keys(associated_perm, version, encrypted_sym_key, encrypted_priv_key)
        values(?, ?, ?, ?)
        """
        for i in range(len(mod_keys)):
            sym = netlib.b64_to_bytes(mod_keys[i][0])
            mod = netlib.b64_to_bytes(mod_keys[i][1])
            add_mod_keys_params = (perm_id, i, sym, mod)
            cur.execute(add_mod_keys_command, add_mod_keys_params)

    db.commit()
    return {
        "success": True,
        "data": None
    }


def remove_permission(user_id: int, leaderboard_id: int, new_read_keys: dict, new_mod_pubkey: Union[bytes, None],
                      new_mod_keys: Union[dict, None]) -> dict:
    update_mod = False
    cur = db.cursor()
    get_perm_command = """
    select permission from permissions
    where user_id = ? and leaderboard = ?
    """
    get_perm_params = (user_id, leaderboard_id)
    cur.execute(get_perm_command, get_perm_params)
    (old_perm,) = cur.fetchone()
    if old_perm == Permissions.Moderate and (new_mod_pubkey is None or new_mod_keys is None):
        return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
    if old_perm == Permissions.Moderate:
        update_mod = True

    delete_permission_command = """
    delete from permissions
    where user_id = ? and leaderboard = ?
    """
    delete_permission_params = (user_id, leaderboard_id)
    cur.execute(delete_permission_command, delete_permission_params)

    get_current_key_versions_command = """
    select read_key_version, mod_pubkey, mod_key_version
    from leaderboards
    where id = ?
    """
    get_current_key_versions_params = (leaderboard_id,)
    cur.execute(get_current_key_versions_command, get_current_key_versions_params)
    (read_key_ver, mod_pubkey, mod_key_ver) = cur.fetchone()
    read_key_ver += 1

    add_new_read_perms_command = """
    insert into read_keys(user, leaderboard, associated_perm, version, encrypted_key)
    select ?, ?, associated_perm, ?, ?
    from read_keys
    left join permissions p on p.id = associated_perm
    where user = ? and leaderboard = ?
    """
    for user in new_read_keys:
        add_new_read_perms_params = (user, leaderboard_id, read_key_ver, new_read_keys[user], user, leaderboard_id)
        cur.execute(add_new_read_perms_command, add_new_read_perms_params)

    if update_mod:
        mod_pubkey = new_mod_pubkey
        mod_key_ver += 1
        add_new_mod_perms_command = """
        insert into mod_keys (user, leaderboard, associated_perm, version, encrypted_sym_key, encrypted_priv_key)
        select ?, ?, associated_perm, ?, ?, ?
        from mod_keys
        left join permissions p on p.id = associated_perm
        where user = ? and leaderboard = ?
        """
        for user in new_mod_keys:
            add_new_mod_perms_params = (user, leaderboard_id, mod_key_ver, new_mod_keys[user][0], new_mod_keys[user][1], user, leaderboard_id)
            cur.execute(add_new_mod_perms_command, add_new_mod_perms_params)

    update_leaderboard_command = """
    update leaderboards
    set read_key_version = ?, mod_pubkey = ?, mod_key_version = ?
    where id = ?
    """
    update_leaderboard_params = (read_key_ver, mod_pubkey, mod_key_ver, leaderboard_id)
    cur.execute(update_leaderboard_command, update_leaderboard_params)
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


def add_proof(request_user_id: int, entry_id: int, filename: str, file: bytes, uploader_key: bytes, mod_key: bytes, mod_key_ver: int) -> dict:
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
        insert into files (entry, name, submission_date, data, uploader_key, mod_key, mod_key_ver)
        values (?, ?, strftime('%s'), ?, ?, ?, ?)
    """
    add_file_params = (entry_id, filename, file, uploader_key, mod_key, mod_key_ver)
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
        select data, uploader_key, mod_key, mod_key_ver, read_key_ver
        from files
        where id = ?
    """
    get_file_params = (file_id,)
    cur.execute(get_file_command, get_file_params)
    (file, uploader_key, mod_key, mod_key_ver, read_key_ver) = cur.fetchone()
    return_dict = {
        "file": netlib.bytes_to_b64(file),
        "uploader_key": netlib.bytes_to_b64(uploader_key),
        "mod_key": netlib.bytes_to_b64(mod_key),
        "mod_key_ver": mod_key_ver,
        "read_key_ver": read_key_ver
    }
    return {
        "success": True,
        "data": return_dict
    }


def list_access_groups(leaderboard_id: int) -> dict:
    cur = db.cursor()
    list_user_perms_command = """
        select u.id, u.identity, coalesce(permission, 0) as perm, pub_key
        from users u
        left join (select * from permissions where leaderboard = ?) p
            on p.user = u.id
        order by perm
    """
    list_user_perms_params = (leaderboard_id, leaderboard_id)
    cur.execute(list_user_perms_command, list_user_perms_params)
    user_list = cur.fetchall()
    returnable_user_list = [(e[0], e[1], e[2], netlib.bytes_to_b64(e[3])) for e in user_list]
    return {
        "success": True,
        "data": returnable_user_list
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


def get_keys(user_id: int, lb_id: int) -> dict:
    cur = db.cursor()
    get_read_keys_command = """
        select version, encrypted_key
        from read_keys
        left join permissions p on p.id = associated_perm
        where user = ? and leaderboard = ?
    """
    get_read_keys_params = (user_id, lb_id)
    cur.execute(get_read_keys_command, get_read_keys_params)
    read_keys = cur.fetchall()
    get_mod_keys_command = """
        select version, encrypted_priv_key, encrypted_sym_key
        from mod_keys
        left join permission p on p.id = associated_perm
        where user = ? and leaderboard = ?
    """
    get_mod_keys_params = (user_id, lb_id)
    cur.execute(get_read_keys_command, get_read_keys_params)
    mod_keys = cur.fetchall()
    return {
        "success": True,
        "data": {
            "read": read_keys,
            "mod": mod_keys
        }
    }


def handle_request(request_user_id: int, request: dict):
    perms = get_leaderboard_perms(request_user_id)
    user_class = get_user_class(request_user_id)
    # Every request needs to have these
    try:
        request_type = request["type"]
        if not isinstance(request_type, int):
            raise TypeError
    except (KeyError, TypeError):
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
        except (KeyError, TypeError):
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
            new_lb_asc = request["leaderboard_ascending"]
            if not isinstance(new_lb_asc, bool):
                raise TypeError
            mod_pubkey = netlib.b64_to_bytes(request["mod_pubkey"])
            creator_read_key = netlib.b64_to_bytes(request["read_key"])
            creator_mod_sym = netlib.b64_to_bytes(request["mod_sym"])
            creator_mod_priv = netlib.b64_to_bytes(request["mod_priv"])
        except (KeyError, TypeError, ValueError):
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return add_leaderboard(request_user_id, new_lb_name, new_lb_asc, mod_pubkey, creator_read_key, creator_mod_sym,
                               creator_mod_priv)

    # Leaderboard: Submit Entry
    if request_type == ResourceRequestType.AddEntry:
        try:
            leaderboard_id = request["leaderboard_id"]
            if not isinstance(leaderboard_id, int):
                raise TypeError
            entry_score = netlib.b64_to_bytes(request["score"])
            comment = netlib.b64_to_bytes(request["comment"])
            uploader_key = netlib.b64_to_bytes(request["user_key"])
            mod_key = netlib.b64_to_bytes(request["mod_key"])
            mod_key_ver = request["mod_key_ver"]
            if not isinstance(mod_key_ver, int):
                raise TypeError
        except (KeyError, TypeError):
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return add_entry(request_user_id, perms, leaderboard_id, entry_score, comment, uploader_key, mod_key, mod_key_ver)

    # Basic: List Users
    if request_type == ResourceRequestType.ListUsers:
        return list_users()

    # Leaderboard: List Unverified
    if request_type == ResourceRequestType.ListUnverified:
        try:
            leaderboard_id = request["leaderboard_id"]
            if not isinstance(leaderboard_id, int):
                raise TypeError
        except (KeyError, TypeError):
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
        except (KeyError, TypeError):
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
        except (KeyError, TypeError):
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return get_user(request_user_id, user_id)

    # Internal
    if request_type == ResourceRequestType.GetSelfID:
        return {
            "success": True,
            "data": request_user_id
        }

    # Entry: Verify Entry
    if request_type == ResourceRequestType.Verify_Entry:
        try:
            entry_id = request["entry_id"]
            if not isinstance(entry_id, int):
                raise TypeError
            score = netlib.b64_to_bytes(request["score"])
            read_key_ver = request["read_key_ver"]
            if not isinstance(read_key_ver, int):
                raise TypeError
            intermediate_comments = request["comments"]
            comments = {int(comment_id): netlib.b64_to_bytes(intermediate_comments[id]) for comment_id in intermediate_comments}
            intermediate_files = request["files"]
            files = {int(file_id): netlib.b64_to_bytes(intermediate_files[file_id]) for file_id in intermediate_files}
        except (KeyError, TypeError):
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return verify_entry(request_user_id, perms, entry_id, score, read_key_ver, comments, files)

    # Entry: Add comment
    if request_type == ResourceRequestType.AddComment:
        try:
            entry_id = request["entry_id"]
            if not isinstance(entry_id, int):
                raise TypeError
            content = netlib.b64_to_bytes(request["content"])
            uploader_key = netlib.b64_to_bytes(request["uploader_key"])
            mod_key = netlib.b64_to_bytes(request["mod_key"])
            mod_key_ver = request["mod_key_ver"]
            if not isinstance(mod_key_ver, int):
                raise TypeError
        except (KeyError, TypeError):
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return add_comment(request_user_id, perms, entry_id, content, uploader_key, mod_key, mod_key_ver)

    # Admin: Remove Leaderboard
    if request_type == ResourceRequestType.RemoveLeaderboard:
        if user_class != UserClass.Administrator:
            return serverlib.bad_request_json(ServerErrCode.InsufficientPermission)
        try:
            leaderboard_id = request["leaderboard_id"]
            if not isinstance(leaderboard_id, int):
                raise TypeError
        except (KeyError, TypeError):
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return remove_leaderboard(leaderboard_id)

    # Entry: Remove Entry
    if request_type == ResourceRequestType.RemoveEntry:
        try:
            entry_id = request["entry_id"]
            if not isinstance(entry_id, int):
                raise TypeError
        except (KeyError, TypeError):
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
        except (KeyError, TypeError):
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return view_permissions(user_id)

    # User: Set Permission
    if request_type == ResourceRequestType.AddPermission:
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
            read_keys = request["read_keys"]
            if not isinstance(read_keys, list):
                raise TypeError
            mod_keys = request["mod_keys"]
            if not (isinstance(mod_keys, list) or mod_keys is None):
                raise TypeError
        except (KeyError, TypeError, ValueError):
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return add_permission(user_id, leaderboard_id, p, read_keys, mod_keys)

    if request_type == ResourceRequestType.RemovePermission:
        if user_class < UserClass.Administrator:
            return serverlib.bad_request_json(ServerErrCode.InsufficientPermission)
        try:
            user_id = request["user_id"]
            if not isinstance(user_id, int):
                raise TypeError
            leaderboard_id = request["leaderboard_id"]
            if not isinstance(leaderboard_id, int):
                raise TypeError
            new_read_keys = request["new_read_keys"]
            if not isinstance(new_read_keys, dict):
                raise TypeError
            new_mod_pub_key = request["new_mod_pubkey"]
            if new_mod_pub_key is not None:
                netlib.b64_to_bytes(new_mod_pub_key)
            new_mod_keys = request["new_mod_keys"]
            if not (isinstance(new_mod_keys, dict) or new_mod_keys is None):
                raise TypeError
        except (KeyError, TypeError):
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return remove_permission(user_id, leaderboard_id, new_read_keys, new_mod_pub_key, new_mod_keys)

    # User: Remove User
    if request_type == ResourceRequestType.RemoveUser:
        if user_class < UserClass.Administrator:
            return serverlib.bad_request_json(ServerErrCode.InsufficientPermission)
        try:
            user_id = request["user_id"]
            if not isinstance(user_id, int):
                raise TypeError
        except (KeyError, TypeError):
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
        except (KeyError, TypeError):
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
            uploader_key = netlib.b64_to_bytes(request["uploader_key"])
            mod_key = netlib.b64_to_bytes(request["mod_key"])
            mod_key_ver = request["mod_key_ver"]
            if not isinstance(mod_key_ver, int):
                raise TypeError
            file = netlib.b64_to_bytes(request["file"])
        except (KeyError, TypeError):
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return add_proof(request_user_id, entry_id, filename, file, uploader_key, mod_key, mod_key_ver)

    # Entry: Download Proof
    if request_type == ResourceRequestType.DownloadProof:
        try:
            file_id = request["file_id"]
            if not isinstance(file_id, int):
                raise TypeError
        except (KeyError, TypeError):
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return download_proof(request_user_id, perms, file_id)

    if request_type == ResourceRequestType.ListAccessGroups:
        try:
            leaderboard_id = request["leaderboard_id"]
            if not isinstance(leaderboard_id, int):
                raise TypeError
        except (KeyError, TypeError):
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
        except (KeyError, TypeError):
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return remove_proof(request_user_id, perms, file_id)

    if request_type == ResourceRequestType.GetKeys:
        try:
            user_id = request["user_id"]
            if not isinstance(user_id, int):
                raise TypeError
            lb_id = request["leaderboard_id"]
            if not isinstance(lb_id, int):
                raise TypeError
        except (KeyError, TypeError):
            return serverlib.bad_request_json(ServerErrCode.MalformedRequest)
        return get_keys(user_id, lb_id)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(30)  # for handshake, don't wait longer than 30 seconds for a packet
        print("Connection opened with {}".format(self.client_address[0]))
        # Initial connection
        try:
            request = netlib.get_dict_from_socket(self.request)
        except BrokenPipeError:
            print("Client Broke Pipe")
            return
        if not request["type"] == ResourceRequestType.PublicKey:
            print("Initial request not for public key, exiting")
            netlib.send_dict_to_socket(serverlib.bad_request_json(ServerErrCode.MalformedRequest), self.request)
            return
        response = serverlib.public_key_response(public_key)
        netlib.send_dict_to_socket(response, self.request)

        # Authentication step
        try:
            request = netlib.get_dict_from_socket(self.request)
        except socket.timeout:
            print("Timed out waiting for authentication, closing socket.")
            netlib.send_dict_to_socket(serverlib.bad_request_json(ServerErrCode.SessionExpired), self.request)
            return
        except BrokenPipeError:
            print("Client Broke Pipe")
            return
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
        expiration_time = signin_request["expiration_time"]
        if time.time() > float(expiration_time):
            print("Token is expired!")
            netlib.send_dict_to_socket(serverlib.bad_request_json(ServerErrCode.MalformedRequest), self.request)
            return
        client_public_key_bytes = netlib.b64_to_bytes(signin_request["pubkey"])
        client_public_key = netlib.deserialize_public_key(client_public_key_bytes)
        if not cryptolib.rsa_verify_str(auth_public_key, token, cryptolib.public_key_hash(public_key) + socket_identity + expiration_time):
            print("Invalid login token, exiting")
            netlib.send_dict_to_socket(serverlib.bad_request_json(ServerErrCode.AuthenticationFailure), self.request)
            return

        # verification
        nonce = os.urandom(32)
        encrypted_nonce = cryptolib.symmetric_encrypt(aes_key, nonce)
        response = {"nonce": netlib.bytes_to_b64(encrypted_nonce), "signature": netlib.bytes_to_b64(cryptolib.rsa_sign(private_key, encrypted_nonce))}
        netlib.send_dict_to_socket(response, self.request)
        try:
            request = netlib.get_dict_from_socket(self.request)
        except socket.timeout:
            print("Timed out waiting for nonce reply, closing socket.")
            netlib.send_dict_to_socket(serverlib.bad_request_json(ServerErrCode.SessionExpired), self.request)
            return
        except BrokenPipeError:
            print("Client Broke Pipe")
            return
        if not request["type"] == ResourceRequestType.NonceReply:
            print("Request type not a NonceReply, exiting")
            netlib.send_dict_to_socket(serverlib.bad_request_json(ServerErrCode.MalformedRequest), self.request)
            return
        encrypted_reply_nonce = netlib.b64_to_bytes(request["nonce"])
        signature = netlib.b64_to_bytes(request["signature"])
        if not cryptolib.rsa_verify(client_public_key, signature, encrypted_reply_nonce):
            print("Signature verification failed")
            netlib.send_dict_to_socket(serverlib.bad_request_json(ServerErrCode.MalformedRequest), self.request)
            return
        reply_nonce = cryptolib.symmetric_decrypt(aes_key, encrypted_reply_nonce)
        if not netlib.bytes_to_int(nonce) + 1 == netlib.bytes_to_int(reply_nonce):
            print("Invalid nonce reply, exiting")
            netlib.send_dict_to_socket(serverlib.bad_request_json(ServerErrCode.AuthenticationFailure), self.request)
            return

        # verified
        netlib.send_dict_to_socket({"success": True, "data": None}, self.request)
        self.request.settimeout(300)
        # Register user if not registered
        print("User {} successfully connected".format(socket_identity))
        cursor = db.cursor()
        register_command = """
            insert or ignore into users(identity, class, registration_date) values(?, ?, strftime('%s'))
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

        while True:
            try:
                request = netlib.get_dict_from_socket(self.request)
            except socket.timeout:
                print("Timed out waiting for packet, closing socket.")
                netlib.send_dict_to_socket(serverlib.bad_request_json(ServerErrCode.SessionExpired), self.request)
                return
            except BrokenPipeError:
                print("Client Broke Pipe")
                return
            print("received {} from {}".format(request, self.client_address[0]))
            encrypted_request = netlib.b64_to_bytes(request["encrypted_request"])
            if not cryptolib.rsa_verify(client_public_key, netlib.b64_to_bytes(request["signature"]), encrypted_request):
                # TODO as above, maybe need a new error code for this
                return serverlib.bad_request_json(ServerErrCode.AuthenticationFailure)
            request = cryptolib.decrypt_dict(aes_key, encrypted_request)
            response = handle_request(socket_user_id, request)
            response_bytes = cryptolib.encrypt_dict(aes_key, response)
            base64_response = netlib.bytes_to_b64(response_bytes)
            response = {"encrypted_response": base64_response, "signature": netlib.bytes_to_b64(cryptolib.rsa_sign(private_key, response_bytes))}
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
            registration_date INTEGER NOT NULL,
            pub_key BLOB NOT NULL
        );
        CREATE TABLE leaderboards (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            creation_date INTEGER NOT NULL,
            ascending BOOLEAN NOT NULL,
            mod_pubkey BLOB NOT NULL,
            read_key_version INTEGER NOT NULL,
            mod_key_version INTEGER NOT NULL
        );
        CREATE TABLE permissions (
            id INTEGER PRIMARY KEY,
            user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            leaderboard INTEGER NOT NULL REFERENCES  leaderboards(id) ON DELETE CASCADE,
            permission INTEGER NOT NULL,
            change_date INTEGER NOT NULL
        );
        CREATE TABLE read_keys (
            associated_perm INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
            version INTEGER NOT NULL,
            encrypted_key BLOB NOT NULL
        );
        CREATE TABLE mod_keys (
            associated_perm INTEGER NOT NULL REFERENCES permissions(id) ON DELETE CASCADE,
            version INTEGER NOT NULL,
            encrypted_sym_key BLOB NOT NULL,
            encrypted_priv_key BLOB NOT NULL
        );
        CREATE TABLE leaderboard_entries (
            id INTEGER PRIMARY KEY,
            user INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            leaderboard INTEGER NOT NULL REFERENCES leaderboards(id) ON DELETE CASCADE,
            score BLOB NOT NULL,
            uploader_key BLOB,
            mod_key BLOB,
            mod_key_ver INTEGER,
            read_key_ver INTEGER,
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
            content BLOB NOT NULL,
            uploader_key BLOB,
            mod_key BLOB,
            mod_key_ver INTEGER,
            read_key_ver INTEGER
        );
        CREATE TABLE files (
            id INTEGER PRIMARY KEY,
            entry INTEGER NOT NULL REFERENCES leaderboard_entries(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            submission_date INTEGER NOT NULL,
            data BLOB NOT NULL,
            uploader_key BLOB,
            mod_key BLOB,
            mod_key_ver INTEGER,
            read_key_ver INTEGER,
        );
    """

    # Filenames
    db_filename = "res_db"
    key_filename = "res_private_key"
    auth_public_key_filename = "auth_public_key"

    # Init Cryptography stuff
    private_key = cryptolib.initialize_key(key_filename)
    public_key = private_key.public_key()
    if not path.exists(auth_public_key_filename):
        print("No Auth server public key found! Please provide an authentication server public key.")
        sys.exit(1)
    with open(auth_public_key_filename, "rb") as key_file:
        auth_public_key: rsa.RSAPublicKey = netlib.deserialize_public_key(key_file.read())
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
