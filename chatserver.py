# chat server
# python 3.5

import sys, socket, getopt, select

# broadcasts chat messages to all clients
# s = socket of client that sent the message, m = message
def broadcast(s, m):
    for sock in clients:
        if sock != serv_sock and sock != s:
            try:
                sock.send(m)
            except:
                print "Unable to send message to client connected to: " + sock
                print "Closing the connection..."
                sock.close()
                clients.remove(sock)
                print "Connection closed."

if __name__ == "__main__":
    # default chatport is 9090
    chatport = 9090
    try:
        opts, args = getopt.getopt(sys.argv[1:], "h", ["sp="])
    except getopt.GetoptError:
        print "usage: chatserver.py -sp <portnumber>"
        sys.exit()
    for opt, arg in opts:
        if opt == "-h":
            # h is for help. it tells you how to use the program.
            print "usage: chatserver.py -sp <portnumber>"
            sys.exit()
        if opt == "-sp":
            chatport = arg
    #list of connected clients (including the server)
    clients = []
    recv_buf = 4096

    # setting up the server socket
    serv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serv_sock.bind(("0.0.0.0", chatport))
    serv_sock.listen(10)

    clients.append(serv_sock)

    print "Server started on port: " + str(chatport)

    while True:
        # Gets all of the sockets that are ready
        read_socks,write_socks,error_socks = select.select(clients,[],[])

        for sock in read_socks:
            if sock == serv_sock:
                # new connections are received in the server socket
                # accept the new connection and add it to the connection list
                new_sock, address = serv_sock.accept()
                clients.append(new_sock)
                print "Client " + str(address) + " has connected."
                # let everyone know that a new member has joined the chat
                # broadcast(new_sock, "New member! Everyone say hi to: " + str(address))
            else:
                # data received from a client that is already connected.
                try:
                    data = sock.recv(recv_buf)
                    if data:
                        broadcast(sock, "\r" + "<FROM " + str(sock.getpeername()) + ">: " + data)
                        print "<" + str(sock.getpeername()) + ">: " + data

                except:
                    # something went wrong, remove the client and close the socket.
                    print "Client " + str(address) + " disconnected."
                    sock.close()
                    clients.remove(sock)
                    continue

    serv_sock.close()
