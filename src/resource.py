"""
json packet contains an identity from the authentication server which has been proved
the identity has to be looked up in a table of permissions
if the person can perform the request they are making according to the table, respond with the
    answer to the request, otherwise respond with an access denied packet.
"""
import socketserver
import json
from enum import Enum, auto
from enums import ResourceRequestType


class UserClass(Enum):
    User = auto()
    Moderator = auto()
    Administrator = auto()


def response_show_leaderboards(string):
    return {
        "type": ResourceRequestType.ShowLeaderboards,
        "string": string
    }


def response_show_one_leaderboard(leaderboard_id):
    # TODO account for leaderboard visibility according to user group?
    return {
        "type": ResourceRequestType.ShowOneLeaderboard,
        "data": db["leaderboards"][leaderboard_id]
    }


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        print("handling packet")
        self.data = self.rfile.readline().strip()
        print("data received")
        request = json.loads(self.data)
        print("received {} from {}".format(self.data, self.client_address[0]))
        # If the database is currently empty (with no registered users) then the first user to connect becomes the admin
        if db["users"] is None:
            admin = (
                request["identity"],
                request["token"],
                UserClass.Administrator
            )
            db["users"] = [admin]
            json.dump(db, db_file)
        if request["type"] == ResourceRequestType.ShowLeaderboards:
            response = response_show_leaderboards("this is the leaderboard!!!")
            self.wfile.write(json.dumps(response).encode() + b"\n")
        elif request["type"] == ResourceRequestType.ShowOneLeaderboard:
            response = response_show_one_leaderboard(request["leaderboard_id"])
            self.wfile.write(json.dumps(response).encode() + b"\n")


if __name__ == "__main__":
    # TODO get this from command line or config file?
    db_filename = "res_db"
    db_file = open(db_filename, "w")
    try:
        db = json.load(db_file)
    except json.decoder.JSONDecodeError:
        db = dict()

    HOST, PORT = "localhost", 8086
    with socketserver.TCPServer((HOST, PORT), Handler) as server:
        server.serve_forever()
