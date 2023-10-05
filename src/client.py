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
import time


def request_token(identity):
    return {"type": "token", "identity": identity}


def request_show_leaderboards(identity, token):
    return {"type": "show_leaderboards", "identity": identity, "token": token}


def main():
    print("Welcome to the leaderboard client application")
    # identity = input("Enter identity: ")
    identity = "Crop Topographer"
    # auth_ip = input("Enter authentication server IP: ")
    auth_ip = socket.gethostbyname(socket.gethostname())
    # auth_port = input("Enter authentication server port: ")
    auth_port = "8085"
    # res_ip = input("Enter resource server IP: ")
    res_ip = socket.gethostbyname(socket.gethostname())
    # res_port = input("Enter resource server port: ")
    res_port = "8086"
    # request_type = input("What is your request type? (show leaderboard): ")
    request_type = "show leaderboard"

    # AF_INET type connections use a tuple of (IP, port)
    auth = socket.socket()
    while True:
        try:
            # TODO I don't think this actually works
            auth.connect((auth_ip, int(auth_port)))
            break
        except (ConnectionRefusedError, OSError):
            print("Connection to Authentication server failed, trying again in 5 seconds...")
            time.sleep(5)
    request = request_token(identity)
    print("sending "+json.dumps(request))
    auth.send(str.encode(json.dumps(request)))
    buffer = bytearray()
    while True:
        try:
            auth.recv_into(buffer)
            print("received " + str(buffer))
            response = json.loads(buffer)
            break
        except json.decoder.JSONDecodeError:
            print("malformed packet received")
    # here is where we should check for errors
    token = response["token"]
    res = socket.socket()
    while True:
        try:
            res.connect((res_ip, int(res_port)))
            break
        except (ConnectionRefusedError, OSError):
            print("Connection to Resource server failed, trying again in 5 seconds...")
            time.sleep(5)
    request = request_show_leaderboards(identity, token)
    res.send(json.dumps(request))
    buffer = bytearray()
    res.recv_into(buffer)
    response = json.loads(buffer)
    # here is where we should check for errors
    print(response["string"])


if __name__ == "__main__":
    main()
