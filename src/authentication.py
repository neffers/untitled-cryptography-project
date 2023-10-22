import socketserver
import json
import struct
import signal
import sys


def response_token(token):
    return {"type": token, "token": token}


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        print("handling packet")
        self.data = self.request.recv(4)
        buffer_len = struct.unpack("!I", self.data)[0]
        self.data = self.request.recv(buffer_len)
        print("data received")
        print("received {} from {}".format(self.data, self.client_address[0]))
        try:
            request = json.loads(self.data)
            response = response_token(request["identity"])
            print("sending {}".format(response))
            response = json.dumps(response).encode()
            buffer = struct.pack("!I", len(response))
            buffer += bytes(response)
            self.request.send(buffer)
        except json.decoder.JSONDecodeError:
            print("Could not interpret packet!")
            # response = return_bad_request("Could not interpret packet.")
def signal_handler(sig, frame):
    print("\nshutting down...")
    server.server_close()
    sys.exit(0)


if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 8085
    signal.signal(signal.SIGINT, signal_handler)
    try:
        server = socketserver.TCPServer((HOST, PORT), Handler)
        print("socket bound successfully")
        server.serve_forever()
    except OSError:
        print("can't bind to " + HOST + ":" + str(PORT))
