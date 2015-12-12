# chat server
# python 3.5
# Joseph Ruane + Neeraj Beri

import sys, socket, getopt, select, common, os, binascii, time

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
users_challenged = []

# IP | Port
users_can_send_pass = []

# list of currently connected users
# username | IP | Port | Public Key | Shared AES key | Shared HKey | Nonce
authed_users = []

# List specifying which users potentially have their client to client keys setup
# In other words which users information were sent to which users
# [user whose info was sent, ""] | [user1 to whom this info was sent, time of sending the info] | .....
A1A2_key_exchanged_user_list = []
A1A2_key_exchanged_user_list_timeout = 600


# verifies a user
def Verify_User(username, password):
    try:
        return user_passes[username] == common.Hash_This(password)
    except:
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

#
def Get_User_Data_with_ip_port(client_ip, client_port):
    currentUserDataList = []
    authdUsersListIndex = 0
    userFound = False
    for i in range(0,len(authed_users)):
        if authed_users[i][1] == client_ip and authed_users[i][2] == client_port:
            currentUserDataList = authed_users[i]
            authdUsersListIndex = i
            userFound = True
            break
        else:
            userFound = False
    return currentUserDataList, userFound, authdUsersListIndex

def Get_User_Data_With_Username(recvdUsername):
    currentUserDataList = []
    authdUsersListIndex = 0
    userFound = False
    for i in range(0,len(authed_users)):
        if authed_users[i][0] == recvdUsername:
            currentUserDataList = authed_users[i]
            authdUsersListIndex = i
            userFound = True
            break
        else:
            userFound = False
    return currentUserDataList, userFound, authdUsersListIndex

def update_A1A2_key_exchanged_user_list(targetUsername, sourceUsername):
    for i in range(0,len(A1A2_key_exchanged_user_list)):
        if A1A2_key_exchanged_user_list[i][0] == targetUsername:
            for j in range(0, len(A1A2_key_exchanged_user_list[i])):
                if A1A2_key_exchanged_user_list[i][j][0] == sourceUsername:
                    A1A2_key_exchanged_user_list[i][j][1] = int(time.time())
                    return
            A1A2_key_exchanged_user_list[i].append([sourceUsername, int(time.time()) + A1A2_key_exchanged_user_list_timeout])

def check_for_duplicate_login(client_username):
    for user in authed_users:
        if user[0] == client_username:
            print "Found duplicate username %s" % client_username
            print A1A2_key_exchanged_user_list
            authed_users.remove(user)
            clients.remove(user[7])
            user[7].close()

def trigger_A1A2_key_refresh(client_username):
    A1UserDataList, A1userFound, A1authdUsersListIndex = Get_User_Data_With_Username(client_username)
    #print A1UserDataList
    #print A1A2_key_exchanged_user_list
    #print authed_users
    for i in range(0, len(A1A2_key_exchanged_user_list)):
        if A1A2_key_exchanged_user_list[i][0] == client_username:
            for j in range(2, len(A1A2_key_exchanged_user_list[i])):
                if A1A2_key_exchanged_user_list[i][j][1] > int(time.time()):
                    A2UserDataList, A2userFound, A2authdUsersListIndex = Get_User_Data_With_Username(A1A2_key_exchanged_user_list[i][j][0])
                    if not A2userFound:
                        print "Target user %s not in authed user list" % A1A2_key_exchanged_user_list[i][j][0]
                        continue
                    A2sendClearText = ''.join(
                        [common.Increment_Nonce(A2UserDataList[6]), common.Get_4byte_IP_Address(A1UserDataList[1]), common.Get_2byte_Port_Number(A1UserDataList[8]), A1UserDataList[3], client_username]
                    )
                    #print A2sendClearText
                    A2HmacAppendedCipherText = common.AES_Encrypt_Add_HMAC(A2sendClearText, A2UserDataList[4], A2UserDataList[5])
                    A2sendData = ''.join([common.Get_Message_ID("server_sends_info_to_client2"), A2HmacAppendedCipherText])
                    sockA2 = A2UserDataList[7]
                    sockA2.send(A2sendData)
                    print "triggered key refresh of %s with %s" % (client_username, A2UserDataList[0])
                    authed_users[A2authdUsersListIndex][6] = common.Increment_Nonce(A2UserDataList[6])
                    time.sleep(0.1)
            return

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
                # print clients
                # let everyone know that a new member has joined the chat
                # broadcast(new_sock, "New member! Everyone say hi to: " + str(address))
            else:
                try:
                    data = sock.recv(recv_buf)
                    if data:
                        client_ip              = sock.getpeername()[0]
                        client_port            = sock.getpeername()[1]
                        client_message_id      = data[:1]
                        client_message_id_name = common.Get_Message_Name(client_message_id)
                        client_message         = data[1:]
                        # Challenge request handling
                        if client_message_id_name == 'login_request':
                            #print("login requested")
                            if Is_User_Challenged(client_ip, client_port) or Can_User_Auth(client_ip, client_port) or Is_User_Authed(client_ip, client_port):
                                continue
                            #print("user has not been authed or sent a challenge")
                            challenge_out, challenge_in = common.Create_Challenge()
                            #print("adding user to list of challenged")
                            users_challenged.append([client_ip, client_port, challenge_out])
                            message_to_client = ''.join([common.Get_Message_ID("challenge_to_client"), challenge_in, challenge_out])
                            #print("sending challenge")
                            sock.send(message_to_client)
                            #print("sent challenge")
                            continue

                        # Challenge response handling
                        if client_message_id_name == 'challenge_response':
                            #print "got a solution!"
                            if (not Is_User_Challenged(client_ip, client_port)) or Can_User_Auth(client_ip, client_port) or Is_User_Authed(client_ip, client_port):
                                continue
                            challenge_output = Get_Challenge_Out(client_ip, client_port)
                            if common.Verify_Challenge_Solution(client_message, challenge_output):
                                users_can_send_pass.append([client_ip, client_port])
                                users_challenged.remove([client_ip, client_port, challenge_output])
                                sock.send(common.Get_Message_ID('challenge_result'))
                                print "Client " + str(address) + " has passed proof of work challenge."
                            else:
                                print "Client " + str(address) + " failed the challenge."
                                continue

                        # Verifies the user login request
                        if client_message_id_name == "user_login":
                            if (not Can_User_Auth(client_ip, client_port)) or Is_User_Authed(client_ip, client_port):
                                continue
                            users_can_send_pass.remove([client_ip, client_port])
                            client_signed_hash = client_message[   :256]
                            iv                 = client_message[256:272]
                            encrypted_AES_key  = client_message[272:528]
                            ciphertext         = client_message[528:   ]
                            unencrypted_AES_key = common.Asymmetric_Decrypt(serv_pri_key, encrypted_AES_key)
                            plaintext = common.Symmetric_Decrypt(ciphertext, unencrypted_AES_key, iv)

                            client_nonce          = plaintext[    :  32]
                            client_ListenPort     = plaintext[32  :  34]
                            client_public_key     = plaintext[34  : 485]
                            client_usernamelength = plaintext[485 : 486]
                            client_username       = plaintext[486 : 486+ord(client_usernamelength)]
                            client_password       = plaintext[486+ord(client_usernamelength) : ]

                            response_message_id = common.Get_Message_ID("login_reply_from_server")

                            # verify login message and user/pass
                            data_to_verify = client_message[256 : ]
                            response_nonce = common.Increment_Nonce(client_nonce)
                            if (not common.Verify_Signature(data_to_verify, client_signed_hash, client_public_key)) or (not Verify_User(client_username, client_password)):
                                yes_or_no = chr(0)
                                random_filler = os.urandom(64)
                                response_plaintext = "".join([yes_or_no,response_nonce,random_filler])
                                response_ciphertext, response_iv = common.Symmetric_Encrypt(response_plaintext, unencrypted_AES_key)
                                response_superCipherText = ''.join([response_iv, response_ciphertext])
                                response_signedHash = common.Get_Signed_Hash(response_superCipherText, serv_pri_key)
                                sendData = "".join([response_message_id, response_signedHash, response_superCipherText])
                                sock.send(sendData)
                                print "invalid user/signature sending \"bad\" response"
                                continue

                            yes_or_no = chr(1)
                            shared_aes  = os.urandom(32)
                            shared_hkey = os.urandom(32)
                            response_plaintext = "".join([yes_or_no,response_nonce,shared_aes,shared_hkey])
                            response_ciphertext, response_iv = common.Symmetric_Encrypt(response_plaintext, unencrypted_AES_key)
                            response_superCipherText = ''.join([response_iv, response_ciphertext])
                            response_signedHash = common.Get_Signed_Hash(response_superCipherText, serv_pri_key)
                            sendData = "".join([response_message_id, response_signedHash, response_superCipherText])
                            sock.send(sendData)
                            
                            # Check if user was already present in authed_users table

                            check_for_duplicate_login(client_username)
                            authed_users.append(
                                [client_username, client_ip, client_port, client_public_key, shared_aes, shared_hkey, response_nonce, sock, common.Get_Integer_Port_from_2byte_Port(client_ListenPort)]
                            )
                            trigger_A1A2_key_refresh(client_username)

                            A1A2_key_exchanged_user_list.append([client_username, ["", ""]])

                            print "User \"" + client_username + "\" has authenticated from " + str(address) + "."
                            #print "sent acceptance message/added user to list of active, authed users"
                            # print authed_users
                            continue

                        # Handles list update request from Client
                        if client_message_id_name == "client_to_server_list_update":
                            currentUserDataList, userFound, authdUsersListIndex = Get_User_Data_with_ip_port(client_ip, client_port)
                            if userFound == False:
                                print "Could not find client IP or Port in the authd users list"
                                continue
                            hmacRecvd = client_message[:32]
                            hmacInput = client_message[32:]
                            shared_hkey = currentUserDataList[5]
                            shared_aes = currentUserDataList[4]
                            if common.Verify_HMAC(hmacInput, hmacRecvd, shared_hkey) == False:
                                print "HMAC verification failed"
                                continue
                            recvdClearText = common.Symmetric_Decrypt(hmacInput[16:], shared_aes, hmacInput[:16])
                            recvdNonce = recvdClearText[:32]
                            recvdUsername = recvdClearText[32:]
                            if recvdNonce != common.Increment_Nonce(currentUserDataList[6]):
                                print "Nonce Verification Failed"
                                continue
                            if recvdUsername != currentUserDataList[0]:
                                print "Username doesn't match the client IP / Port combo"
                                continue
                            # HMAC, nonce and username is verified at this point, next we prepare the response
                            response_nonce = common.Increment_Nonce(recvdNonce)
                            userListMessage = ""
                            for i in range(0, len(authed_users)):
                                userListMessage = ''.join([userListMessage, chr(len(authed_users[i][0])), authed_users[i][0]])
                            # using chr(0) as a delimiter between user list and number of users
                            userListMessageWithLength = ''.join([userListMessage, chr(0), str(len(authed_users))])
                            # print userListMessage
                            response_plaintext = ''.join([response_nonce, userListMessageWithLength])
                            # print response_plaintext
                            response_ciphertext, response_iv = common.Symmetric_Encrypt(response_plaintext, shared_aes)
                            response_hmacInput = ''.join([response_iv, response_ciphertext])
                            response_hmac = common.get_HMAC(response_hmacInput, shared_hkey)
                            response_message_id = common.Get_Message_ID("server_to_client_user_list")
                            sendData = ''.join([response_message_id, response_hmac, response_hmacInput])
                            sock.send(sendData)
                            # updating Nonce to response_Nonce in authed_users
                            authed_users[authdUsersListIndex][6] = response_nonce
                            print "sent user list to username = %s" % recvdUsername
                            continue

                        ##################### Handles the support for client to client communication ##################
                        # Handles the Client1 request to server to initiate communication with client2 and sends a headsup to Client2
                        if client_message_id_name == "client1_request_to_server_for_client2":
                            A1UserDataList, A1userFound, A1authdUsersListIndex = Get_User_Data_with_ip_port(client_ip, client_port)
                            if A1userFound == False:
                                print "Could not find source client IP or Port in the authd users list"
                                continue
                            recvdClearText = common.Verify_HMAC_Decrypt_AES(client_message, A1UserDataList[5], A1UserDataList[4])
                            #print recvdClearText
                            A1recvdNonce = recvdClearText[:32]
                            if A1recvdNonce != common.Increment_Nonce(A1UserDataList[6]):
                                print "Nonce Verification Failed"
                                continue
                            recvdA1Username = recvdClearText[33:33+ord(recvdClearText[32])]
                            if recvdA1Username != A1UserDataList[0]:
                                print "Username doesn't match the client IP / Port combo"
                                continue
                            # HMAC, nonce and username is verified at this point, next we need to verify A2 username in authed user list
                            authed_users[A1authdUsersListIndex][6] = A1recvdNonce
                            A1UserDataList[6] = A1recvdNonce
                            #print recvdA1Username
                            recvdA2Username = recvdClearText[34+len(recvdA1Username):33+len(recvdA1Username)+ord(recvdClearText[32+len(recvdA1Username)])]
                            #print recvdA2Username
                            A2UserDataList, A2userFound, A2authdUsersListIndex = Get_User_Data_With_Username(recvdA2Username)
                            if not A2userFound:
                                print "Target user %s not in authed user list" % recvdA2Username
                                continue
                            A2sendClearText = ''.join(
                                [common.Increment_Nonce(A2UserDataList[6]), common.Get_4byte_IP_Address(A1UserDataList[1]), common.Get_2byte_Port_Number(A1UserDataList[8]), A1UserDataList[3], recvdA1Username]
                            )
                            #print A2sendClearText
                            A2HmacAppendedCipherText = common.AES_Encrypt_Add_HMAC(A2sendClearText, A2UserDataList[4], A2UserDataList[5])
                            A2sendData = ''.join([common.Get_Message_ID("server_sends_info_to_client2"), A2HmacAppendedCipherText])
                            sockA2 = A2UserDataList[7]
                            sockA2.send(A2sendData)
                            authed_users[A2authdUsersListIndex][6] = common.Increment_Nonce(A2UserDataList[6])
                            update_A1A2_key_exchanged_user_list(recvdA2Username, recvdA1Username)
                            print "User \"" + recvdA1Username + "\" is trying to set up a key with \"" + recvdA2Username + "\"."
                            continue

                            # Handles the Client2 response and sends a confirmation back to client1
                        if client_message_id_name == "client2_reply_to_server":
                            A2UserDataList, A2userFound, A2authdUsersListIndex = Get_User_Data_with_ip_port(client_ip, client_port)
                            if A2userFound == False:
                                print "Could not find source client IP or Port in the authd users list"
                                continue
                            recvdClearText = common.Verify_HMAC_Decrypt_AES(client_message, A2UserDataList[5], A2UserDataList[4])
                            A2recvdNonce = recvdClearText[:32]
                            if A2recvdNonce != common.Increment_Nonce(A2UserDataList[6]):
                                print "Nonce Verification Failed"
                                continue
                            authed_users[A2authdUsersListIndex][6] = A2recvdNonce
                            A2UserDataList[6] = A2recvdNonce
                            recvdA1Username = recvdClearText[32:]
                            A1UserDataList, A1userFound, A1authdUsersListIndex = Get_User_Data_With_Username(recvdA1Username)
                            if A1userFound == False:
                                print "Source user specified not in authed user list"
                                # print "length of authed users list = %s" % len(authed_users)
                                continue
                            A1sendPlainText = ''.join(
                                [common.Increment_Nonce(A1UserDataList[6]), common.Get_4byte_IP_Address(A2UserDataList[1]), common.Get_2byte_Port_Number(A2UserDataList[8]), A2UserDataList[3], A2UserDataList[0]]
                            )
                            A1HmacAppendedCipherText = common.AES_Encrypt_Add_HMAC(A1sendPlainText, A1UserDataList[4], A1UserDataList[5])
                            A1sendData = ''.join([common.Get_Message_ID("server_reply_to_client1"), A1HmacAppendedCipherText])
                            sockA1 = A1UserDataList[7]
                            sockA1.send(A1sendData)
                            authed_users[A1authdUsersListIndex][6] = common.Increment_Nonce(A1UserDataList[6])
                            update_A1A2_key_exchanged_user_list(recvdA1Username, A2UserDataList[0])
                            print "Done with Key exchange support to clients"
                            continue
                except:
                #    # something went wrong, remove the client and close the socket.
                    print "Client " + str(address) + " disconnected."
                    sock.close()
                    clients.remove(sock)
                    continue
    serv_sock.close()
