import json
import os
import os.path

# SERVER CLASS FOR STORING
class Server:
    def __init__(self, name, ip, port):
        self.name = name
        self.ip = ip
        self.port = port

    def rename(self, newname):
        self.name = newname

    def readdress(self, newip):
        self.ip = newip

    def readdress(self, newport):
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
path = './client_testing.json'
fcheck = os.path.exists(path)

# IF FILE DOES NOT EXIST, INITIALIZE IT
if fcheck == False:
    with open("client_testing.json", "w") as f:
        server_dict = {}
        server_dict["servers"] = []
        json.dump(server_dict, f, indent = 4)

# GLOBAL SERVER COUNT
servercount = 0

# MAIN FUNCTION
def maindisplay():
    # CLEAR SCREEN TO BEGIN
    os.system('cls')

    # KEEP TRACK OF SERVER COUNT
    global servercount

    # SET HEADER FOR LIST
    print("Server List:\n[#]   Name:                   IP:                Port:")

    # DISPLAY SERVER LIST
    with open("client_testing.json", "r") as f:
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
            servercount = servercount + 1

# SWITCH FOR MENU AND SERVER
connect = False

# MENU INTERFACE
def mainoptions():
    global connect
    while connect == False:

        # DISPLAY MAIN STUFF
        maindisplay()

        # IF NO AUTH SERVER, ADD IMMEDIATELY
        if servercount == 0:
            print("\nYou do not yet have an auth server. Please add one now.")
            newname = input("Give a name for the server. Please use only 20 characters or less\n")
            if len(newname) > 20:
                newname = newname[:20]
            newip = input("Give the ip to the server.\n")
            newport = input("Give the port to the server.\n")
            newserver = Server(newname, newip, newport)
            newserver.ssave("client_testing.json")

            maindisplay()

        # DISPLAY OPTIONS
        print("\nOptions: \n[C] connect to server \n[A] add server listing \n[E] edit server listing \n[R] remove server listing \n[Q] quit application")

        # TAKE INPUT
        key = input("\nPlease choose the corresponding key.\n")

        # CONNECT
        if key == 'C' or key == 'c':
            print("connect")

            # SWITCH BOOLEAN FOR SERVER INTERFACE
            connect = True

        # ADD
        if key == 'A' or key == 'a':
            newname = input("Give a name for the server. Please use only 20 characters or less\n")
            if len(newname) > 20:
                newname = newname[:20]
            newip = input("Give the ip to the server.\n")
            newport = input("Give the port to the server.\n")
            newserver = Server(newname, newip, newport)
            newserver.ssave("client_testing.json")

        # EDIT

        # REMOVE

        # QUIT
        if key == "Q" or key == 'q':
            quit()

# SERVER INTERFACE - ADD IN 'client.py' ACCORDINGLY
def mainserver():
    
    # END BY SWITCHING CONNECT BOOLEAN OFF, STARTING MENU INTERFACE
    connect = False

# MAIN MAIN
# SWITCHES BETWEEN INTERFACES VIA BOOLEAN 'connect' 
while 1 == 1:
    mainoptions()
    mainserver()