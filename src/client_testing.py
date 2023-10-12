import json
import os
import os.path

# SERVER CLASS FOR STORING
class Server:
    def __init__(self, name, address):
        self.name = name
        self.address = address

    def rename(self, newname):
        self.name = newname

    def readdress(self, newaddress):
        self.address = newaddress

    def ssave(self, filename):
        with open(filename) as f:
            sdata = json.load(f)
            parse = sdata["servers"]
            newentry = {'name': self.name, 'address': self.address}
            parse.append(newentry)
        with open(filename, 'w') as f:
            json.dump(sdata, f, indent = 4)

# BASIC TESTING DONE FOR SAVE FEATURE
# serv1 = Server("auth", "www.pitt.edu")
# serv1.ssave("client_testing.json")
# serv2 = Server("auth2", "www.pitt2.edu")
# serv2.ssave("client_testing.json")

# CHECK IF JSON FILE OF SERVERS EXISTS
path = './client_testing.json'
fcheck = os.path.exists(path)

# IF FILE DOES NOT EXIST, INITIALIZE IT
if fcheck == False:
    with open("client_testing.json", "w") as f:
        server_dict = {}
        server_dict["servers"] = []
        json.dump(server_dict, f, indent = 4)

# BASIC TESTING DONE FOR SAVE FEATURE (AGAIN)
# serv1 = Server("auth", "www.pitt.edu")
# serv1.ssave("client_testing.json")

# MAIN FUNCTION
def maindisplay():
    # CLEAR SCREEN TO BEGIN
    os.system('cls')

    # SET HEADER FOR LIST
    print("Server List:\n[#]   Name   Address")

    # DISPLAY SERVER LIST
    with open("client_testing.json", "r") as f:
        sdata = json.load(f)
        parse = sdata["servers"]
        count = 1
        for i in parse:
            print("["+str(count)+"]"+"   "+parse[count-1]['name']+"   "+parse[count-1]['address'])
            count = count + 1

# MAIN FUNCTION
def mainoptions():
    # DISPLAY OPTIONS
    print("\nOptions: \n[C] connect to server \n[A] add server listing \n[E] edit server listing \n[R] remove server listing \n[Q] quit application")

    # TAKE INPUT
    key = input("\nPlease choose the corresponding key.\n")

    # CONNECT
    if key == 'C' or key == 'c':
        print("conntect")

    # ADD
    if key == 'A' or key == 'a':
        newname = input("Give a name for the server.\n")
        newaddress = input("Give the address to the server.\n")
        newserver = Server(newname, newaddress)
        newserver.ssave("client_testing.json")

    # QUIT
    if key == "Q" or key == 'q':
        quit()

while 1 == 1:
    maindisplay()
    mainoptions()