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


# servers do sock.bind(("", port)) sock.listen() and sock.accept() -> (conn, (ip, pair)) where conn can send/recv
# sock.sendall(bytes)
# server should loop through connections and sock.setblocking(False) so it can receive and handle.
#   callbacks?
# sock.recv_into(buffer)
# sock.close()


# in the future, all of these packet types will be located wherever they are sent
# to unpack something, you import the module that sent it I guess?
class request_token:
    def __init__(self, identity):
        self.identity = identity

class response_token:
    def __init__(self, token):
        self.token = token

class request_show_leaderboards:
    def __init__(self, identity, token):
        self.identity = identity
        self.token = token

class response_show_leaderboards:
    def __init__(self, string):
        self.string = string

if __name__ == "__main__":
    print("Welcome to the leaderboard client application")
    identity = input("Enter identity: ")
    auth_ip = input("Enter authentication server IP: ")
    auth_port = input("Enter authentication server port: ")
    res_ip = input("Enter resource server IP: ")
    res_port = input("Enter resource server port: ")
    request = input("What is your request? (show leaderboard): ")

    # json might encode the type of packet in the object type, so we don't need to restate it as a field
    # AF_INET type connections use a tuple of (IP, port)
    auth = socket.socket()
    auth.connect((auth_ip, auth_port))
    request = request_token(identity)
    auth.send(json.dumps(request))
    buffer = bytearray()
    response_bytes = auth.recv_into(buffer)
    response = json.loads(buffer)
    # here is where we should check for errors
    token = response.token
    res = socket.socket()
    res.connect((res_ip, res_port))
    request = request_show_leaderboards(identity, token)
    res.send(json.dumps(request))
    buffer = bytearray()
    response_bytes = res.recv_into(buffer)
    response = json.loads(buffer)
    print(response.string)
