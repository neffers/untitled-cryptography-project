"""
json packet contains an identity from the authentication server which has been proved
the identity has to be looked up in a table of permissions
if the person can perform the request they are making according to the table, respond with the
    answer to the request, otherwise respond with an access denied packet.
"""
import socketserver
import json


def response_show_leaderboards(string):
    return {"type": "show_leaderboards", "string": string}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        print("handling packet")
        self.data = self.rfile.readline().strip()
        print("data received")
        request = json.loads(self.data)
        print("received {} from {}".format(self.data, self.client_address[0]))
        if request["type"] == "show leaderboards":
            response = response_show_leaderboards("this is the leaderboard!!!")
            self.wfile.write(json.dumps(response).encode() + b"\n")


if __name__ == "__main__":
    HOST, PORT = "localhost", 8086
    with socketserver.TCPServer((HOST, PORT), Handler) as server:
        server.serve_forever()
