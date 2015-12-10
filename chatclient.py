# chat client
# python 3.5

import sys, socket, getopt, select, thread, common, time, os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

def prompt():
    sys.stdout.write("+> ")
    sys.stdout.flush()

# This functions implements the login challenge sequence
def Request_For_Login():
    sent_solution = False
    #print "login request messageID = %s" % common.Get_Message_ID("login_request")
    sockClient.send(common.Get_Message_ID("login_request"))
    #print "sent challenge request"
    # RETURN FALSE IF IT TAKES OVER A MINUTE TO DO THIS, do a while that breaks after a certain time
    # ALSO WRAP THIS IN A TRY CATCH FOR SOCKET TIMEOUTS
    # timeout_start = time.time() ---- could be used for timeout on listening socket
    # timeout = 10 ---- could be used for timeout on listening socket
    # while time.time() < timeout_start + timeout
    while True:
        recvData = sockClient.recv(recv_buf)
        if recvData:
            if recvData[:1] == common.Get_Message_ID("challenge_to_client") and sent_solution:
                print "Invalid message ID"
                sys.exit()
            if recvData[:1] == common.Get_Message_ID("challenge_result") and not sent_solution:
                print "Invalid message ID"
                sys.exit()
            if recvData[:1] == common.Get_Message_ID("challenge_to_client"):
                hash_input = recvData[1:15]
                hash_output = recvData[15:]
                solution = common.Solve_Challenge(hash_output, hash_input)
                sendData = ''.join([common.Get_Message_ID("challenge_response"), solution])
                sockClient.send(sendData)
                sent_solution = True
            if recvData[:1] == common.Get_Message_ID("challenge_result"):
                return True
    return False

# This function asks the user for credentials and implements the user login sequence
def Initiate_Login_Sequence(client_private_key):
    username = raw_input("Enter username:\n")
    password = raw_input("Enter password:\n")
    Nonce = os.urandom(32)
    serialized_pri_key = common.Serialize_Pri_Key(client_private_key)
    serialized_pub_key = common.Serialize_Pub_Key(client_private_key.public_key())
    username_length = len(username)
    if username_length > 255:
        sys.exit("username supplied was too long")
    clearText = ''.join([Nonce, common.Get_2byte_Port_Number(listenPort), serialized_pub_key, chr(username_length), username, password])
    tempAESkey = os.urandom(32)
    cipherText, iv = common.Symmetric_Encrypt(clearText, tempAESkey)
    encryptedAESkey = common.Asymmetric_Encrypt(serialized_serv_pub_key, tempAESkey)
    superCipherText = ''.join([iv, encryptedAESkey, cipherText])
    signedHash = common.Get_Signed_Hash(superCipherText, serialized_pri_key)
    messageID = common.Get_Message_ID("user_login")
    sendData = ''.join([messageID, signedHash, superCipherText])
    sockClient.send(sendData)
    while True:
        recvData = sockClient.recv(recv_buf)
        if not recvData:
            continue
        if recvData[0:1] != common.Get_Message_ID("login_reply_from_server"):
            print "Invalid message ID"
            sys.exit()
        signedHash = recvData[1:257]
        iv = recvData[257:273]
        cipherText = recvData[273:]
        if common.Verify_Signature(recvData[257:], signedHash, serialized_serv_pub_key) == False:
            sys.exit("Server signature verification Failed\nMITM possible\nExiting...")
        clearText = common.Symmetric_Decrypt(cipherText, tempAESkey, iv)
        if clearText[1:33] != common.Increment_Nonce(Nonce):
            sys.exit("Nonce not verified\nReplay Attack Possible\nExiting...")
        return clearText, username

def Ask_Server_For_List(username):
    nonceServer = common.Increment_Nonce(clientDataTable[1][6])
    clearText = ''.join([nonceServer, username])
    cipherText, iv = common.Symmetric_Encrypt(clearText, clientDataTable[1][4])
    hmacInputData = ''.join([iv, cipherText])
    hmac = common.get_HMAC(hmacInputData, clientDataTable[1][5])
    sendData = ''.join([common.Get_Message_ID("client_to_server_list_update"), hmac, hmacInputData])
    sockClient.send(sendData)
    clientDataTable[1][6] = nonceServer
    return

def Receive_and_Display_List(recvdMessage):
        recvdPlainText = common.Verify_HMAC_Decrypt_AES(recvdMessage, clientDataTable[1][5], clientDataTable[1][4])
        if recvdPlainText[:32] != common.Increment_Nonce(clientDataTable[1][6]):
            print "Nonce failed"
            sys.exit()
        clientDataTable[1][6] = recvdPlainText[:32]
        userListMessageWithLength = recvdPlainText[32:]
        numUsers = 0
        listUsers = []
        index = 0
        print "Online Users: (" + userListMessageWithLength[index+1:] + ")"
        while True:
            usernameLength = ord(userListMessageWithLength[index])
            if usernameLength == 0:
                break
            username = userListMessageWithLength[index+1:index+1+usernameLength]
            listUsers.append(username)
            print username
            index = index + 1 + usernameLength
        return listUsers

def Client_Key_Exchange_Request_to_Server(userInput, username):
    targetUsername = userInput[5:].split()[0]
    A1A2MESSAGE = userInput[6+len(targetUsername)]
    nonceServer = common.Increment_Nonce(clientDataTable[1][6])
    plainText = ''.join([nonceServer, chr(len(username)), username, chr(len(targetUsername)), targetUsername])
    hmac_cipherText = common.AES_Encrypt_Add_HMAC(plainText, clientDataTable[1][4], clientDataTable[1][5])
    sendData = ''.join([common.Get_Message_ID("client1_request_to_server_for_client2"), hmac_cipherText])
    sockClient.send(sendData)
    clientDataTable[1][6] = nonceServer
    return A1A2MESSAGE

# def Client_Key_Exchange_Server_to_A2():

def Get_User_Data_With_Username(recvdUsername):
    recvdUserDataList = []
    clientTableListIndex = 0
    recvdUserFound = False
    for i in range(0,len(clientDataTable)):
        if clientDataTable[i][0] == recvdUsername:
            recvdUserDataList = clientDataTable[i]
            clientTableListIndex = i
            recvdUserFound = True
            break
        else:
            recvdUserFound = False
    return recvdUserDataList, recvdUserFound, clientTableListIndex

def Get_User_Data_With_Socket(recvdSocket):
    recvdUserDataList = []
    clientTableListIndex = 0
    recvdUserFound = False
    for i in range(0,len(clientDataTable)):
        if clientDataTable[i][7] == recvdSocket:
            recvdUserDataList = clientDataTable[i]
            clientTableListIndex = i
            recvdUserFound = True
            break
        else:
            recvdUserFound = False
    return recvdUserDataList, recvdUserFound, clientTableListIndex

def SendMessagetoA2(A1A2MESSAGE, loggedInUsername, A2UserDataList, A2clientTableListIndex):
    sendNonce = common.Increment_Nonce(A2UserDataList[6])
    sendTimeStamp = str(int(time.time()))
    #print sendNonce
    #print sendTimeStamp
    #print chr(len(loggedInUsername))
    #print loggedInUsername
    #print A1A2MESSAGE
    sendPlainText = ''.join([sendNonce, sendTimeStamp, chr(len(loggedInUsername)), loggedInUsername, A1A2MESSAGE])
    sendData = ''.join(
        [common.Get_Message_ID("A1_to_A2_send_message"), common.AES_Encrypt_Add_HMAC(sendPlainText, A2UserDataList[4], A2UserDataList[5])]
    )
    A2UserDataList[7].send(sendData)
    clientDataTable[A2clientTableListIndex][6] = sendNonce
    #print "sent \"%s\" to %s" % (A1A2MESSAGE, A2UserDataList[0])
    return

def A1A2KeyExchange(A2UserDataList):
    A1A2_AES_Key = os.urandom(32)
    A1A2_HMAC_Key = os.urandom(32)
    A1A2_Nonce = os.urandom(32)
    A1A2PlainText = ''.join([A1A2_Nonce, A1A2_HMAC_Key, loggedInUsername])
    A1A2AES_CipherText, iv = common.Symmetric_Encrypt(A1A2PlainText, A1A2_AES_Key)
    A1A2encryptedAESkey = common.Asymmetric_Encrypt(A2UserDataList[3], A1A2_AES_Key)
    A1A2SuperCipherText = ''.join([iv, A1A2encryptedAESkey, A1A2AES_CipherText])
    A1A2SignedHash = common.Get_Signed_Hash(A1A2SuperCipherText, common.Serialize_Pri_Key(client_private_key))
    sendData = ''.join([common.Get_Message_ID("A1_to_A2_key_setup"), A1A2SignedHash, A1A2SuperCipherText])
    A2sock = A2UserDataList[7]
    try:
        A2sock.connect((A2UserDataList[1], A2UserDataList[2]))
        allSockets.append(A2sock)
        #print "socket connected to %s" % A2UserDataList[0]
        A2sock.send(sendData)
        A2UserDataList, A2UserFound, A2clientTableListIndex = Get_User_Data_With_Username(A2UserDataList[0])
        clientDataTable[A2clientTableListIndex][4] = A1A2_AES_Key
        clientDataTable[A2clientTableListIndex][5] = A1A2_HMAC_Key
        clientDataTable[A2clientTableListIndex][6] = A1A2_Nonce
        while True:
            data = A2sock.recv(recv_buf)
            if data:
                recvdMessageID = data[:1]
                recvdMessage = data[1:]
                A2recvdPlainText = common.Verify_HMAC_Decrypt_AES(recvdMessage, A1A2_HMAC_Key, A1A2_AES_Key)
                A2recvdNonce = A2recvdPlainText
                if A2recvdNonce != common.Increment_Nonce(A1A2_Nonce):
                    print "A2 received Nonce in A1A2 key exchange failed"
                    clientDataTable[A2clientTableListIndex][4] = ""
                    break
                clientDataTable[A2clientTableListIndex][6] = A2recvdNonce
                break

    except:
        print "Something is wrong with the client 2 connection\nA1A2 key exchange failed"
    return

def Add_Row_To_Client_Data_Table(username, IP, Port, PubKey, AESkey, HMACkey, Nonce, socket):
    i = len(clientDataTable)
    clientDataTable.append([username, IP, Port, PubKey, AESkey, HMACkey, Nonce, socket])
    return

def Print_Syntax():
    print "\nChat Client available commands:"
    print "list                      : receives updated list of connected users from server"
    print "logout                    : logs out the current user"
    print "text <username> <message> : sends message to username\n"
    return

def Keep_Listening():
    while True:
        read_socks,write_socks,error_socks = select.select(allSockets,[],[])
        for sock in read_socks:
            if sock == sockListen:
                # could be a new client initiating connection
                # accept the new connection and add it to the connection list
                new_sock, address = sockListen.accept()
                allSockets.append(new_sock)
            elif sock == sockClient:
                # Data received from the server
                    data = sock.recv(recv_buf)
                    if data:
                        recvdMessageID = data[:1]
                        recvdMessage = data[1:]
                        if recvdMessageID == common.Get_Message_ID("server_to_client_user_list"):
                            Receive_and_Display_List(recvdMessage)
                        elif recvdMessageID == common.Get_Message_ID("server_sends_info_to_client2"):
                            recvdPlainText = common.Verify_HMAC_Decrypt_AES(recvdMessage, clientDataTable[1][5], clientDataTable[1][4])
                            if recvdPlainText[:32] != common.Increment_Nonce(clientDataTable[1][6]):
                               print "Nonce failed"
                               sys.exit()
                            clientDataTable[1][6] = recvdPlainText[:32]
                            recvedIPA1 = common.Get_String_IP_from_4byte_IP(recvdPlainText[32:36])
                            recvdPortA1 = common.Get_Integer_Port_from_2byte_Port(recvdPlainText[36:38])
                            recvdPubA1 = recvdPlainText[38:489]
                            recvdUsernameA1 = recvdPlainText[489:]
                            Add_Row_To_Client_Data_Table(recvdUsernameA1, recvedIPA1, recvdPortA1, recvdPubA1, "", "", "", "")
                            sendPlainText = ''.join([common.Increment_Nonce(clientDataTable[1][6]), recvdUsernameA1])
                            HmacAppendedCipherText = common.AES_Encrypt_Add_HMAC(sendPlainText, clientDataTable[1][4], clientDataTable[1][5])
                            sendData = ''.join([common.Get_Message_ID("client2_reply_to_server"), HmacAppendedCipherText])
                            sockClient.send(sendData)
                            clientDataTable[1][6] = common.Increment_Nonce(clientDataTable[1][6])
                        elif recvdMessageID == common.Get_Message_ID("server_reply_to_client1"):
                            recvdPlainText = common.Verify_HMAC_Decrypt_AES(recvdMessage, clientDataTable[1][5], clientDataTable[1][4])
                            if recvdPlainText[:32] != common.Increment_Nonce(clientDataTable[1][6]):
                                print "Nonce Failed"
                                sys.exit()
                            clientDataTable[1][6] = recvdPlainText[:32]
                            recvedIPA2 = common.Get_String_IP_from_4byte_IP(recvdPlainText[32:36])
                            recvdPortA2 = common.Get_Integer_Port_from_2byte_Port(recvdPlainText[36:38])
                            recvdPubA2 = recvdPlainText[38:489]
                            recvdUsernameA2 = recvdPlainText[489:]
                            socketA2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            socketA2.settimeout(2)
                            Add_Row_To_Client_Data_Table(recvdUsernameA2, recvedIPA2, recvdPortA2, recvdPubA2, "", "", "", socketA2)
                            A2UserDataList = [recvdUsernameA2, recvedIPA2, recvdPortA2, recvdPubA2, "", "", "", socketA2]
                            A1A2KeyExchange(A2UserDataList)
            else:
                data = sock.recv(recv_buf)
                if data:
                    recvdMessageID = data[:1]
                    recvdMessage = data[1:]
                    if recvdMessageID == common.Get_Message_ID("A1_to_A2_key_setup"):
                        A1A2SignedHash      = recvdMessage[:256]
                        iv                  = recvdMessage[256:272]
                        A1A2encryptedAESkey = recvdMessage[272:528]
                        A1A2CipherText      = recvdMessage[528:]
                        A1A2_aes_key = common.Asymmetric_Decrypt(serialized_pri_key, A1A2encryptedAESkey)
                        A1A2plainText = common.Symmetric_Decrypt(A1A2CipherText, A1A2_aes_key, iv)
                        A1A2Nonce = A1A2plainText[:32]
                        A1A2hmacKey = A1A2plainText[32:64]
                        A1userName = A1A2plainText[64:]
                        A1UserDataList, A1UserFound, A1clientTableListIndex = Get_User_Data_With_Username(A1userName)
                        if not common.Verify_Signature(recvdMessage[256:], A1A2SignedHash, A1UserDataList[3]):
                            print "Signature Verification from A1 in A1A2 key setup failed"
                            continue
                        clientDataTable[A1clientTableListIndex][4] = A1A2_aes_key
                        clientDataTable[A1clientTableListIndex][5] = A1A2hmacKey
                        clientDataTable[A1clientTableListIndex][6] = common.Increment_Nonce(A1A2Nonce)
                        clientDataTable[A1clientTableListIndex][7] = sock
                        A2A1responsePlainText = common.Increment_Nonce(A1A2Nonce)
                        A2A1responseCipherText = common.AES_Encrypt_Add_HMAC(A2A1responsePlainText, A1A2_aes_key, A1A2hmacKey)
                        A2A1sendData = ''.join([common.Get_Message_ID("A2_to_A1_ack"), A2A1responseCipherText])
                        sock.send(A2A1sendData)
                        continue
                    if recvdMessageID == common.Get_Message_ID("A1_to_A2_send_message"):
                        A1UserDataList, A1UserFound, A1clientTableListIndex = Get_User_Data_With_Socket(sock)
                        #print "received A1 to A2 message from %s on socket = %s" % (A1UserDataList[0], sock)
                        A1recvdPlainText = common.Verify_HMAC_Decrypt_AES(recvdMessage, A1UserDataList[5], A1UserDataList[4])
                        if A1recvdPlainText[:32] != common.Increment_Nonce(A1UserDataList[6]):
                            print "Nonce Verification Failed in A1 to A2 send message"
                            print "received Nonce = %s" % A1recvdPlainText[:32]
                            print "self Incremented Nonce = %s" % common.Increment_Nonce(A1UserDataList[6])
                            continue
                        clientDataTable[A1clientTableListIndex][6] = common.Increment_Nonce(A1UserDataList[6])
                        A1recvdTimeStamp = time.ctime(int(A1recvdPlainText[32:42]))
                        A1recvdUsername = A1recvdPlainText[43:43+ord(A1recvdPlainText[42])]
                        A1recvdMessage = A1recvdPlainText[43+ord(A1recvdPlainText[42]):]
                        print "\n<%s> <%s>: %s" % (A1recvdTimeStamp, A1recvdUsername, A1recvdMessage)
                        prompt()
                        A1responsePlainText = common.Increment_Nonce(clientDataTable[A1clientTableListIndex][6])
                        A1responseCipherText = common.AES_Encrypt_Add_HMAC(A1responsePlainText, A1UserDataList[4], A1UserDataList[5])
                        sendData = ''.join([common.Get_Message_ID("A2_to_A1_send_message"), A1responseCipherText])
                        sock.send(sendData)
                        #print "sent Ack back to %s on socket = %s" % (A1UserDataList[0], A1UserDataList[7])
                        clientDataTable[A1clientTableListIndex][6] = common.Increment_Nonce(clientDataTable[A1clientTableListIndex][6])
                        continue
                    if recvdMessageID == common.Get_Message_ID("A2_to_A1_send_message"):
                        #print "Test A2 to A1 send message start"
                        A2UserDataList, A2UserFound, A2clientTableListIndex = Get_User_Data_With_Socket(sock)
                        A2recvdPlainText = common.Verify_HMAC_Decrypt_AES(recvdMessage, A2UserDataList[5], A2UserDataList[4])
                        if A2recvdPlainText[:32] != common.Increment_Nonce(A2UserDataList[6]):
                            print "Nonce Verification Failed in A2 to A1 message Ack"
                            continue
                        clientDataTable[A2clientTableListIndex][6] = common.Increment_Nonce(clientDataTable[A2clientTableListIndex][6])
                        #print "Received Nonce from A2 in ack = %s" % clientDataTable[A2clientTableListIndex][6]
                        #print "Ack received"
                        continue


                    # elif recvdMessageID == common.Get_Message_ID("A1_to_A2_send_message"):





                # Data received from other Connected Clients
#                data = sock.recv(recv_buf)
#                if data:
#                   recvdMessageID = data[:1]
#                    recvdMessage = data[1:]





# server public key pair

####################################################################
################## Main Program - Start ############################
####################################################################

serv_pub_key_path = "server_keypair/server_public_key.pem"
serialized_serv_pub_key = ""
with open(serv_pub_key_path, "rb") as key_file:
    serialized_serv_pub_key = key_file.read()

clientDataTable = [
    ["Username", "IP", "Port", "PublicKey", "AESkey", "HMACkey", "Nonce", "Socket"]
]

listenPort = 0
allSockets = []
loggedInUsername = ""
serialized_pri_key = ""
serialized_pub_key = ""


if __name__ == "__main__":
    #list of connected clients (including the server)
    recv_buf = 4096
    ##### Get the command line arguments and use them as IP Address and port number
    argList = sys.argv
    i = 0
    for i in range(0,len(argList)):
        if argList[i] == "-sip":
            serverIP = (argList[i+1])

        if argList[i] == "-sp":
            serverPort = int(argList[i+1])
    sockClient = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sockClient.settimeout(2)
    sockListen = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sockListen.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sockListen.bind(("0.0.0.0", 0))
    sockListen.listen(10)
    listenPort = sockListen.getsockname()[1]
    allSockets.append(sockClient)
    allSockets.append(sockListen)
    ##### connecting to the server
    try:
        sockClient.connect((serverIP, serverPort))
    except:
        print "Something is wrong with the connection."
        print "Check connection parameters."
        print "usage: chatclient.py -sip <IP Address> -sp <Port>"
        sys.exit()
    #print "Connected!"

    ##### Initiate login challenge sequence and exit if failed
    if Request_For_Login() == False:
        sys.exit("Failed Initial Challenge Verification\nCheck challenge hashing module\nExiting...")

    ##### Generate RSA key pair for client
    client_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    serialized_pri_key = common.Serialize_Pri_Key(client_private_key)
    ##### Initiate login authorization sequence for this user and get the clear text
    for i in range(0,5):
        loginReply, username = Initiate_Login_Sequence(client_private_key)
        if loginReply[:1] == chr(1):
            break
        else:
            if i == 4:
                sys.exit("Incorrect username or password\nAll attempts exhausted\nExiting...")
            else:
                print "Incorrect username or password\nPlease try again (Remaining Attempts = %s)" % (4-i)
    #print "credentials accepted!"
    ##### Store the values in clientDataTable
    ##### login reply format:
    ##### YES/NO (1 byte) | Nonce+1 (32 bytes) | AES symmetric key (32 bytes) | HMAC symmetric key (32 bytes)
    Add_Row_To_Client_Data_Table(
        "SERVER", serverIP, serverPort, serialized_serv_pub_key, loginReply[33:65], loginReply[65:97], loginReply[1:33], sockClient
    )
    #print "Logged in as %s" % username
    #print "Added Server Details to the database\n"
    #print "client data table #rows = %s" % len(clientDataTable)
    ##### At this point User is logged in and the program just waits for user input here
    ##### which could be either list update or logout or Client to Client messaging
    ##### So we 'll keep scanning for user input at this time
    ##### Since we also need to listen to sockets, below line starts a new independent thread to scan the sockets
    loggedInUsername = username
    thread.start_new_thread(Keep_Listening, ())
    Print_Syntax()
#    try:
    while True:
        time.sleep(0.1)
        prompt()
        # Gets all of the sockets that are ready
        userInput = raw_input()
        if userInput == "list":
            Ask_Server_For_List(username)
        elif userInput[:5] == "text ":
            if len(userInput.split()) < 2:
                print "Not enough arguments"
                continue
            A2Username = userInput.split()[1]
            if len(userInput) <= 6 + len(A2Username):
                print "Not enough arguments"
                continue
            A2UserDataList, A2UserFound, A2clientTableListIndex = Get_User_Data_With_Username(A2Username)
            A1A2MESSAGE = userInput[6+len(A2Username):]
            if not A2UserFound or A2UserDataList[4] == "":
                MESSAGE = Client_Key_Exchange_Request_to_Server(userInput, username)
                timeout_start = time.time()
                timeout = 10
                while True:
                    time.sleep(0.1)
                    if time.time() > timeout_start + timeout:
                        print "Timed out...\nNo response from either server or the client"
                        break
                    A2UserDataList, A2UserFound, A2clientTableListIndex = Get_User_Data_With_Username(A2Username)
                    if not A2UserFound or A2UserDataList[4] == "":
                        continue
                    else:
                        break
            # print A2UserDataList
            #print "length of client data table = %s" % len(clientDataTable)
            # print clientDataTable
            if A2UserFound and A2UserDataList[4] != "":
                SendMessagetoA2(A1A2MESSAGE, loggedInUsername, A2UserDataList, A2clientTableListIndex)


            # timeout_start = time.time() #---- could be used for timeout on listening socket
            # timeout = 10 # in seconds
            # while time.time() < timeout_start + timeout:
        elif userInput == "print":
            print "length of client data table = %s" % len(clientDataTable)
            print clientDataTable
        elif userInput == "help":
            Print_Syntax()
        else:
            continue



#    except:
#        print "Invalid Input\nExiting..."
#        sys.exit()




    # Start listening on the socket on a separate thread
    # thread.start_new_thread(keep_listening, ())
