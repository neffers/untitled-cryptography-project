import socket
import json
import threading


def response_token(token):
    return {"type": token, "token": token}


def recv_loop(conn, addr):
    print("connection established with "+addr)
    while True:
        buffer = bytearray()
        while True:
            try:
                conn.recv_into(buffer)
                print("packet received from " + addr)
                request = json.loads(buffer)
                break
            except json.decoder.JSONDecodeError:
                print("malformed packet received")
        print("packet contents: "+str(buffer.decode()))
        response = response_token(request["identity"])
        conn.send(json.dumps(response))


def main():
    # port = input("Enter port number: ")
    port = "8085"
    server = socket.socket()
    server.bind(("", int(port)))
    server.listen()
    while True:
        conn, addr = server.accept()
        threading.Thread(target=recv_loop, args=[conn, addr[0]]).run()


if __name__ == "__main__":
    main()
