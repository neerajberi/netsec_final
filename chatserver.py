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
# IP | Port | Challenge hash output(first 32bits)
users_challenged = [] # initially empty
# example of how you add a user to this list when you receive a request for a challenge
#users_challenged.append(['129.0.0.1', 58920, os.urandom(4)])
#users_challenged.append(['129.0.0.2', 58920, os.urandom(4)])

# IP | Port
users_can_send_pass = []
#users_can_send_pass.append(['129.0.0.2', 58920])

# list of currently connected users
# username | IP | Port | Public Key | Shared AES key | Shared HKey | Nonce
authed_users = [] # initially empty
# example of how a user would be added to this list
#                    username | IP       | Port | Public Key | Shared AES key | Shared HKey   | Nonce
#authed_users.append(['jack', '129.0.0.3', '9090', serv_pub_key, os.urandom(32), os.urandom(32), os.urandom(32)])

# verifies a user
def Verify_User(username, password):
    if user_passes[username] == common.Hash_This(password):
        return True
    else:
        return False

# determines whether or not a user can answer a challenge yet.
def Is_User_Challenged(ip, port):
    for user in users_challenged:
        if user[0] == ip and user[1] == port:
            return True
    return False

# gets the challenge output for a challenged user
def Get_Challenge_Out(ip, port):
    for user in users_challenged:
        if user[0] == ip and user[1] == port:
            return user[2]

# returns a boolean saying whether or not a user can authenticate, ie has passed the challenge
def Can_User_Auth(ip, port):
    for user in users_can_send_pass:
        if user[0] == ip and user[1] == port:
            return True
    return False

# not sure if this is good or not
def Is_User_Authed(ip, port):
    for user in authed_users:
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
                #try: ################################## commented to see exceptions in detail
                    data = sock.recv(recv_buf)
                    if data:
                        # THIS IS WHERE ALL THE PROCESSING AND STUFF ACTUALLY HAPPENS
                        # PROBABLY GOING TO JUST HAND THE SOCK AND DATA OFF TO A HELPER
                        # TO KEEP THINGS CLEAN
                        # vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv

                        client_ip              = sock.getpeername()[0]
                        client_port            = sock.getpeername()[1]
                        client_message_id      = int(data[:1])
                        client_message_id_name = common.Get_Message_Name(client_message_id)
                        client_message         = data[1:]
                        print "client info <" + str(client_ip) + ":" + str(client_port) + ">"
                        print "client message: " + client_message_id_name

                        # Challenge request handling
                        if client_message_id_name == 'login_request':
                            print("login requested")
                            if Is_User_Challenged(client_ip, client_port) or Can_User_Auth(client_ip, client_port) or Is_User_Authed(client_ip, client_port):
                                continue
                            print("user has not been authed or sent a challenge")
                            challenge_out, challenge_in = common.Create_Challenge()
                            print("adding user to list of challenged")
                            users_challenged.append([client_ip, client_port, challenge_out])
                            message_to_client = ''.join([str(common.Get_Message_ID("challenge_to_client")), challenge_in, challenge_out])
                            print("sending challenge")
                            sock.send(message_to_client)
                            print("sent challenge")
                            continue

                        # Challenge response handling
                        if client_message_id_name == 'challenge_response':
                            print "got a solution!"
                            if (not Is_User_Challenged(client_ip, client_port)) or Can_User_Auth(client_ip, client_port) or Is_User_Authed(client_ip, client_port):
                                continue
                            print("user has not been authed and has been sent a challenge")
                            print "user challenged list"
                            print users_challenged
                            challenge_output = Get_Challenge_Out(client_ip, client_port)
                            if common.Verify_Challenge_Solution(client_message, challenge_output):
                                print "solution checks out!"
                                users_can_send_pass.append([client_ip, client_port])
                                users_challenged.remove([client_ip, client_port, challenge_output])
                                sock.send(str(common.Get_Message_ID('challenge_result')))
                            else:
                                print "solution doesn't check out!"
                                continue

                        # ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                        # THIS IS WHERE ALL THE PROCESSING AND STUFF ACTUALLY HAPPENS
                        # PROBABLY GOING TO JUST HAND THE SOCK AND DATA OFF TO A HELPER
                        # TO KEEP THINGS CLEAN
                #except: ################################ commented to see exceptions in detail
                #    # something went wrong, remove the client and close the socket.
                #    print "Client " + str(address) + " disconnected."
                #    sock.close()
                #    clients.remove(sock)
                #    continue
    serv_sock.close()
