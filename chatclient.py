# chat client
# python 3.5

import sys, socket, getopt, select

# prompts the user for input
def prompt():
    sys.stdout.write("+> ")
    sys.stdout.flush()

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
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)

    # connecting to the server
    try:
        s.connect((serverip, serverport))
    except:
        print "Something is wrong with the connection."
        print "Check connection parameters."
        sys.exit()
    print "Connected!"
    prompt()

    while True:
        sockets = [sys.stdin, s]

        # Gets all of the sockets that are ready
        read_socks,write_socks,error_socks = select.select(sockets,[],[])

        for sock in read_socks:
            if sock == s:
                data = sock.recv(recv_buf)
                if data:
                    # if we received data, display that data.
                    sys.stdout.write(data)
                    prompt()
                    continue
                # if we didnt receive data, we were disconnected
                print "\nDisconnected!"
                sys.exit()
            else:
                # entering message for the user
                m = sys.stdin.readline()
                s.send(m)
                prompt()
