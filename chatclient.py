# chat client
# python 3.5

########### NOT WORKING YET ##############

import sys, socket, getopt, select, thread
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

def prompt():
    sys.stdout.write("+> ")
    sys.stdout.flush()

def keep_listening():
    rawReceivedMessage = sockClient.recv(recv_buf)
    messageID = rawReceivedMessage[0:7]

if __name__ == "__main__":
    recv_buf = 4096
    # default port is 9090
    serverip = "localhost"
    serverport = 9090
    try:
        opts, args = getopt.getopt(sys.argv[1:], "h", ["sp="])
    except getopt.GetoptError:
        print "usage: chatclient.py -sip <serverip> -sp <serverport>"
        sys.exit()
    for opt, arg in opts:
        if opt == "-h":
            # h is for help. it tells you how to use the program.
            print "usage: chatclient.py -sip <serverip> -sp <serverport>"
            sys.exit()
        if opt == "-sp":
            serverport = int(arg)
        elif opt == "-sip":
            serverip = arg
    sockClient = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sockClient.settimeout(2)

    # connecting to the server
    try:
        sockClient.connect((serverip, serverport))
    except:
        print "Something is wrong with the connection."
        print "Check connection parameters."
        sys.exit()
    print "Connected!"
    prompt()
    username = input("Enter username:\n")
    password = input("Enter password:\n")
    clientPrivateKey = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    sockClient.send("00000000")

