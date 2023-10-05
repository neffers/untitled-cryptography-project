import socketserver
import json


def response_token(token):
    return {"type": token, "token": token}


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        print("handling packet")
        self.data = self.rfile.readline().strip()
        print("data received")
        request = json.loads(self.data)
        print("received {} from {}".format(self.data, self.client_address[0]))
        response = response_token(request["identity"])
        self.wfile.write(json.dumps(response).encode() + b"\n")


if __name__ == "__main__":
    HOST, PORT = "localhost", 8085
    with socketserver.TCPServer((HOST, PORT), Handler) as server:
        server.serve_forever()
