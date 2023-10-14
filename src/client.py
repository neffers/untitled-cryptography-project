"""
set your identity and authentication server once, to be stored on disk unless modified
pick from a list of previously connected resource servers or add a resource server
once you pick a server, pick a request to make and send the request and identity to the AS
when you receive the permission packet from AS, send the identity, request type, and permissions
    to the RS you selected earlier
when you receive the response from the RS, display results
you can then make another request using that same AS response (which violates complete mediation)
    so maybe you have to ask the AS for another response actually?
or you can quit the client application
"""

import asyncio
import json
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

async def main():
    print("Welcome to the leaderboard client application")
    # identity = input("Enter identity: ")
    identity = "Crop Topographer"
    # auth_ip = input("Enter authentication server IP: ")
    auth_ip = "127.0.0.1"
    # auth_port = input("Enter authentication server port: ")
    auth_port = "8085"
    # res_ip = input("Enter resource server IP: ")
    res_ip = "127.0.0.1"
    # res_port = input("Enter resource server port: ")
    res_port = "8086"
    # request_type = input("What is your request type? (show leaderboards): ")
    request_type = "show leaderboards"

    print("trying to connect to {}:{}".format(auth_ip, auth_port))
    reader, writer = await asyncio.open_connection(auth_ip, int(auth_port))
    print("connection successful")
    # TODO what happens if auth server not connecting?
    request = request_token(identity)
    print("writing "+json.dumps(request))
    writer.write(bytes(json.dumps(request) + "\n", "utf-8"))
    await writer.drain()
    print("write successful, reading...")
    response_data = await reader.read()
    response = json.loads(response_data.decode())
    # TODO here is where we should check for errors
    token = response["token"]

    reader, writer = await asyncio.open_connection(res_ip, int(res_port))
    # TODO what happens if res server not connecting?
    request = request_show_leaderboards(identity, token)
    writer.write(bytes(json.dumps(request) + "\n", "utf-8"))
    await writer.drain()
    response_data = await reader.readline()
    response = json.loads(response_data.decode())
    # TODO here is where we should check for errors
    string = response["string"]
    print(string)

    writer.close()
    await writer.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
