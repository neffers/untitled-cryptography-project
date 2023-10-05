"""
json packet contains an identity from the authentication server which has been proved
the identity has to be looked up in a table of permissions
if the person can perform the request they are making according to the table, respond with the
    answer to the request, otherwise respond with an access denied packet.
"""

import socket
import json

# servers do sock.bind(("", port)) sock.listen() and sock.accept() -> (conn, (ip, pair)) where conn can send/recv
# sock.sendall(bytes)
# server should loop through connections and sock.setblocking(False) so it can receive and handle.
#   callbacks?
# sock.recv_into(buffer)
# sock.close()

def response_show_leaderboards(string):
    return {"type": "show_leaderboards", "string": string}







