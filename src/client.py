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

import socket
import json

def request_token(identity):
    return {"type": "token", "identity": identity}

def request_show_leaderboards(identity, token):
    return {"type": "show_leaderboards", "identity": identity, "token": token}

if __name__ == "__main__":
    print("Welcome to the leaderboard client application")
    identity = input("Enter identity: ")
    auth_ip = input("Enter authentication server IP: ")
    auth_port = input("Enter authentication server port: ")
    res_ip = input("Enter resource server IP: ")
    res_port = input("Enter resource server port: ")
    request = input("What is your request? (show leaderboard): ")

    # AF_INET type connections use a tuple of (IP, port)
    auth = socket.socket()
    auth.connect((auth_ip, auth_port))
    request = request_token(identity)
    auth.send(json.dumps(request))
    buffer = bytearray()
    response_bytes = auth.recv_into(buffer)
    response = json.loads(buffer)
    # here is where we should check for errors
    token = response["token"]
    res = socket.socket()
    res.connect((res_ip, res_port))
    request = request_show_leaderboards(identity, token)
    res.send(json.dumps(request))
    buffer = bytearray()
    response_bytes = res.recv_into(buffer)
    response = json.loads(buffer)
    # here is where we should check for errors
    print(response["string"])
