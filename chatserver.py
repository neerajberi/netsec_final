# chat server
# python 3.5

import sys, socket, getopt, select, common, os

# server private/public key pair
serv_pri_key_path = "server_keypair/server_private_key.pem"
serv_pub_key_path = "server_keypair/server_public_key.pem"
with open(serv_pri_key_path, "rb") as key_file:
    serv_pri_key = key_file.read()
with open(serv_pub_key_path, "rb") as key_file:
    serv_pub_key = key_file.read()

# list of users and their associated passwords (IGNORING THE SALT FOR NOW)
# username | salted-password | salt
user_passes = {
    'jack': common.Hash_This('4098'),
    'sape': common.Hash_This('4139'),
    'sap1': common.Hash_This('4132'),
    'sap2': common.Hash_This('4136'),
    'sap3': common.Hash_This('4134')
}

# list of challenged users
# IP | Port | Challenge hash output(first 32bits) | Can send pass?
users_challenged = [] # initially empty
# example of how you add a user to this list when you receive a request for a challenge
users_challenged.append(['129.0.0.1', '9090', os.urandom(4), False])
users_challenged.append(['129.0.0.2', '9090', os.urandom(4), True])

# list of currently connected users
# username | IP | Port | Public Key | Shared AES key | Shared HKey | Nonce
authed_users = [] # initially empty
# example of how a user would be added to this list
#                    username | IP       | Port | Public Key | Shared AES key | Shared HKey   | Nonce
authed_users.append(['jack', '129.0.0.3', '9090', serv_pub_key, os.urandom(32), os.urandom(32), os.urandom(32)])

# verifies a user
def Verify_User(username, password):
    if user_passes[username] == common.Hash_This(password):
        return True
    else:
        return False

# determines whether or not a user can answer a challenge yet.
def Is_User_Challenged(ip, port):
    for user in users_challenged:
        print(user)
        if user[0] == ip and user[1] == port:
            return True
    return False

# returns a boolean saying whether or not a user can authenticate, ie has passed the challenge
def Can_User_Auth(ip, port):
    for user in users_challenged:
        print(user)
        if user[0] == ip and user[1] == port:
            return user[2]
    return False

# not sure if this is good or not
def Is_User_Authed(ip, port):
    for user in authed_users:
        print(user)
        if user[0] == ip and user[1] == port:
            return True
    return False

if __name__ == "__main__":
    #list of connected clients (including the server)
    clients = []
    recv_buf = 4096
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
    # setting up the server socket
    serv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serv_sock.bind(("0.0.0.0", chatport))
    serv_sock.listen(10)
    #
    clients.append(serv_sock)
    print "Server started on port: " + str(chatport)
    #
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
                        print "<" + str(sock.getpeername()) + ">: " + data
                        # THIS IS WHERE ALL THE PROCESSING AND STUFF ACTUALLY HAPPENS
                        # PROBABLY GOING TO JUST HAND THE SOCK AND DATA OFF TO A HELPER
                        # TO KEEP THINGS CLEAN
                except:
                    # something went wrong, remove the client and close the socket.
                    print "Client " + str(address) + " disconnected."
                    sock.close()
                    clients.remove(sock)
                    continue
    serv_sock.close()
