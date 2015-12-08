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
    print "login request messageID = %s" % common.Get_Message_ID("login_request")
    sockClient.send(common.Get_Message_ID("login_request"))
    print "sent challenge request"
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
                print("solved it!")
                sendData = ''.join([common.Get_Message_ID("challenge_response"), solution])
                sockClient.send(sendData)
                print("solution sent")
                sent_solution = True
            if recvData[:1] == common.Get_Message_ID("challenge_result"):
                print("CAN SEND PASS")
                return True
    return False

# This function asks the user for credentials and implements the user login sequence
def Initiate_Login_Sequence(client_private_key):
    username = raw_input("Enter username:\n")
    password = raw_input("Enter password:\n")
    Nonce = os.urandom(32)
    #print Nonce
    serialized_pri_key = common.Serialize_Pri_Key(client_private_key)
    serialized_pub_key = common.Serialize_Pub_Key(client_private_key.public_key())
    #print serialized_pri_key
    #print serialized_pub_key
    username_length = len(username)
    if username_length > 255:
        sys.exit("username supplied was too long")
    clearText = ''.join([Nonce, serialized_pub_key, chr(username_length), username, password])
    tempAESkey = os.urandom(32)
    cipherText, iv = common.Symmetric_Encrypt(clearText, tempAESkey)
    encryptedAESkey = common.Asymmetric_Encrypt(serialized_serv_pub_key, tempAESkey)
    superCipherText = ''.join([iv, encryptedAESkey, cipherText])
    signedHash = common.Get_Signed_Hash(superCipherText, serialized_pri_key)
    messageID = common.Get_Message_ID("user_login")
    sendData = ''.join([messageID, signedHash, superCipherText])
    sockClient.send(sendData)
    print "sent the user/pass combo!"
    #print encryptedAESkey
    #print "length of encrypted hash = %s" % len(signedHash)
    #print "length of IV = %s" % len(iv)
    #print "length of encAESkey = %s" % len(encryptedAESkey)
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
        print "nonce was good bruh"
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

def Receive_and_Display_List():
    while True:
        recvData = sockClient.recv(recv_buf)
        if not recvData:
            continue
        if recvData[0:1] != common.Get_Message_ID("server_to_client_user_list"):
            print "Invalid message ID received from server"
            sys.exit()
        recvdPlainText = common.Verify_HMAC_Decrypt_AES(recvData[1:], clientDataTable[1][5], clientDataTable[1][4])
        if recvdPlainText[:32] != common.Increment_Nonce(clientDataTable[1][6]):
            print "Nonce failed"
            sys.exit()
        clientDataTable[1][6] = recvdPlainText[:32]
        userListMessageWithLength = recvdPlainText[32:]
        numUsers = 0
        listUsers = []
        index = 0
        print "Online Users:"
        while True:
            usernameLength = ord(userListMessageWithLength[index])
            if usernameLength == 0:
                break
            username = userListMessageWithLength[index+1:index+1+usernameLength]
            listUsers.append(username)
            print username
            index = index + 1 + usernameLength
        print "number of online users %s" % userListMessageWithLength[index+1:]
        return listUsers


def Add_Row_To_Client_Data_Table(username, IP, Port, PubKey, AESkey, HMACkey, Nonce):
    i = len(clientDataTable)
    clientDataTable.append([username, IP, Port, PubKey, AESkey, HMACkey, Nonce])
    return


#def keep_listening():
#    while True:
#        rawReceivedMessage = sockClient.recv(recv_buf)
#        messageID = rawReceivedMessage[0:7]
#        messageName = common.Get_Message_Name(messageID)
#        if messageName == "challenge_to_client":

# server public key pair

####################################################################
################## Main Program - Start ############################
####################################################################

serv_pub_key_path = "server_keypair/server_public_key.pem"
serialized_serv_pub_key = ""
with open(serv_pub_key_path, "rb") as key_file:
    serialized_serv_pub_key = key_file.read()

clientDataTable = [
    ["Username", "IP", "Port", "PublicKey", "AESkey", "HMACkey", "Nonce"]
]

if __name__ == "__main__":
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

    ##### connecting to the server
    try:
        sockClient.connect((serverIP, serverPort))
    except:
        print "Something is wrong with the connection."
        print "Check connection parameters."
        print "usage: chatclient.py -sip <IP Address> -sp <Port>"
        sys.exit()
    print "Connected!"

    ##### Initiate login challenge sequence and exit if failed
    if Request_For_Login() == False:
        sys.exit("Failed Initial Challenge Verification\nCheck challenge hashing module\nExiting...")

    ##### Generate RSA key pair for client
    client_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

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
    print "credentials accepted!"
    ##### Store the values in clientDataTable
    ##### login reply format:
    ##### YES/NO (1 byte) | Nonce+1 (32 bytes) | AES symmetric key (32 bytes) | HMAC symmetric key (32 bytes)
    Add_Row_To_Client_Data_Table(
        "SERVER", serverIP, serverPort, serialized_serv_pub_key, loginReply[33:65], loginReply[65:97], loginReply[1:33]
    )
    print "Logged in as %s" % username
    print "Added Server Details to the database\n"
    print "client data table #rows = %s" % len(clientDataTable)
    ##### At this point User is logged in and the program just waits for user input here
    ##### which could be either list update or logout or Client to Client messaging
    ##### So we 'll keep scanning for user input at this time

    print "\nChat Client available commands:"
    print "list                      : receives updated list of connected users from server"
    print "logout                    : logs out the current user"
    print "text <username> <message> : sends message to username "

#    try:
    while True:
        prompt()
        userInput = raw_input()
        if userInput == "list":
            Ask_Server_For_List(username)
            listUsers = Receive_and_Display_List()



#    except:
#        print "Invalid Input\nExiting..."
#        sys.exit()




    # Start listening on the socket on a separate thread
    # thread.start_new_thread(keep_listening, ())
