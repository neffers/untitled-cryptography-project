import json
import os
import os.path
import asyncio
from os import system, name

# SERVER CLASS FOR STORING
class Server:
    def __init__(self, name, ip, port):
        self.name = name
        self.ip = ip
        self.port = port

    def rename(self, newname):
        self.name = newname

    def reip(self, newip):
        self.ip = newip

    def report(self, newport):
        self.port = newport

    def ssave(self, filename):
        with open(filename) as f:
            sdata = json.load(f)
            parse = sdata["servers"]
            newentry = {'name': self.name, 'ip': self.ip, 'port': self.port}
            parse.append(newentry)
        with open(filename, 'w') as f:
            json.dump(sdata, f, indent = 4)

# CHECK IF JSON FILE OF SERVERS EXISTS
path = './client_db.json'
fcheck = os.path.exists(path)

# IF FILE DOES NOT EXIST, INITIALIZE IT
if fcheck == False:
    with open("client_db.json", "w") as f:
        server_dict = {}
        server_dict["servers"] = []
        json.dump(server_dict, f, indent = 4)

# GLOBAL SERVER COUNT
servercount = 0

# CLEAR SCREEN TO KEEP CLEAN
def clear_screen():
    if name == 'nt':
        system('cls')
    else:
        system('clear')

# MAIN FUNCTION
def maindisplay():
    # CLEAR SCREEN TO BEGIN
    clear_screen()

    # KEEP TRACK OF SERVER COUNT
    global servercount

    # SET HEADER FOR LIST
    print("Server List:\n[#]   Name:                   IP:                Port:")

    # DISPLAY SERVER LIST
    with open("client_db.json", "r") as f:
        sdata = json.load(f)
        parse = sdata["servers"]
        count = 1
        for i in parse:
            namedisplay = parse[count-1]['name']+"                        "
            ipdisplay = parse[count-1]['ip']+"                 "
            namedisplay = namedisplay[:24]
            ipdisplay = ipdisplay[:19]


            print("["+str(count)+"]"+"   "+namedisplay+ipdisplay+parse[count-1]['port'])
            count = count + 1
        servercount = len(parse)

# MENU INTERFACE
def mainoptions():
    while True:

        # DISPLAY MAIN STUFF
        maindisplay()

        # IF NO AUTH SERVER, ADD IMMEDIATELY
        if servercount == 0:
            print("\nYou do not yet have an auth server. Please add one now.")
            newname = input("Give a name for the server. Please use only 20 characters or less.\n")
            if len(newname) > 20:
                newname = newname[:20]
            newip = input("Give the ip to the server.\n")
            newport = input("Give the port to the server.\n")
            newserver = Server(newname, newip, newport)
            newserver.ssave("client_db.json")

            maindisplay()

        # DISPLAY OPTIONS
        print("\nOptions: \n[C] connect to server \n[A] add server listing \n[E] edit server listing \n[R] remove server listing \n[Q] quit application")

        # TAKE INPUT
        key = input("\nPlease choose the corresponding key.\n")

        # CONNECT
        if key == 'C' or key == 'c':
            ckey = input("Enter the # of the server that you would like to connect to.\n")
            ckey = int(ckey)
            if ckey < 1 or ckey > servercount:
                break
            with open("client_db.json", "r") as f:
                sdata = json.load(f)
                parse = sdata["servers"]
                connip = parse[ckey-1]['ip']
                connport = parse[ckey-1]['port']
            asyncio.run(mainserver(connip, connport))

        # ADD
        if key == 'A' or key == 'a':
            newname = input("Give a name for the server. Please use only 20 characters or less.\n")
            if len(newname) > 20:
                newname = newname[:20]
            newip = input("Give the ip to the server.\n")
            newport = input("Give the port to the server.\n")
            newserver = Server(newname, newip, newport)
            newserver.ssave("client_db.json")

        # EDIT
        if key == 'E' or key == 'e':
            ekey = input("Enter the # of the server that you would like to edit.\n")
            ekey = int(ekey)
            if ekey < 0 or ekey > servercount:
                break
            ekey2 = input("What would you like to edit? Enter 1 for name, 2 for IP, 3 for port.\n")
            if ekey2 == '1':
                newname = input("Give a new name for the server. Please use only 20 characters or less.\n")
                if len(newname) > 20:
                    newname = newname[:20]
                with open("client_db.json") as f:
                    sdata = json.load(f)
                    parse = sdata["servers"]
                    parse[ekey-1] = {'name': newname, 'ip': parse[ekey-1]['ip'], 'port': parse[ekey-1]['port']}
                with open("client_db.json", 'w') as f:
                    json.dump(sdata, f, indent = 4)
            if ekey2 == '2':
                newip = input("Give the new ip for the server.\n")
                with open("client_db.json") as f:
                    sdata = json.load(f)
                    parse = sdata["servers"]
                    parse[ekey-1] = {'name': parse[ekey-1]['name'], 'ip': newip, 'port': parse[ekey-1]['port']}
                with open("client_db.json", 'w') as f:
                    json.dump(sdata, f, indent = 4)
            if ekey2 == '3':
                newport = input("Give the new port for the server.\n")
                with open("client_db.json") as f:
                    sdata = json.load(f)
                    parse = sdata["servers"]
                    parse[ekey-1] = {'name': parse[ekey-1]['name'], 'ip': parse[ekey-1]['ip'], 'port': newport}
                with open("client_db.json", 'w') as f:
                    json.dump(sdata, f, indent = 4)

        # REMOVE
        if key == 'R' or key == 'r':
            rkey = input("Enter the # of the server that you would like to remove.\n")
            rkey = int(rkey)
            if rkey < 0 or rkey > servercount:
                break
            with open("client_db.json") as f:
                    sdata = json.load(f)
                    parse = sdata["servers"]
                    parse.remove({'name': parse[rkey-1]['name'], 'ip': parse[rkey-1]['ip'], 'port': parse[rkey-1]['port']})
            with open("client_db.json", 'w') as f:
                json.dump(sdata, f, indent = 4)

        # QUIT
        if key == "Q" or key == 'q':
            quit()

def request_token(identity):
    return {"type": "token", "identity": identity}

def request_show_leaderboards(identity, token):
    return {"type": "show leaderboards", "identity": identity, "token": token}

# SERVER INTERFACE - ADD IN 'client.py' ACCORDINGLY
async def mainserver(resip, resport):
    clear_screen()

    with open("client_db.json", "r") as f:
        sdata = json.load(f)
        parse = sdata["servers"]
        auth_ip = parse[0]['ip']
        auth_port = parse[0]['port']

    print("Trying to connect to {}:{}".format(auth_ip, auth_port))
    reader, writer = await asyncio.open_connection(auth_ip, int(auth_port))
    print("Connection successful.")

    identity = input("What is your username?")
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
    reader, writer = await asyncio.open_connection(resip, int(resport))

    while True:
        request_type = input("What request would you like to make?")
        
        if request_type == "quit":
            break

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
    mainoptions()