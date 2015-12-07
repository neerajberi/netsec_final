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
        return False
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
        #if clearText[1:33] != Nonce + 1:
        #    sys.exit("Nonce not verified\nReplay Attack Possible\nExiting...")
        return clearText

def Add_Row_To_Client_Data_Table(username, IP, Port, PubKey, AESkey, HMACkey, Nonce):
    i = len(clientDataTable)
    clientDataTable[i][0] = username
    clientDataTable[i][1] = IP
    clientDataTable[i][2] = Port
    clientDataTable[i][3] = PubKey
    clientDataTable[i][4] = AESkey
    clientDataTable[i][5] = HMACkey
    clientDataTable[i][6] = Nonce

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
        loginReply = Initiate_Login_Sequence(client_private_key)
        if loginReply[0] == "1":
            break
        else:
            if i == 4:
                sys.exit("Incorrect username or password\nAll attempts exhausted\nExiting...")
            else:
                print "Incorrect username or password\nPlease try again (Remaining Attempts = %s)" % (4-i)
    ##### Store the values in clientDataTable
    ##### login reply format:
    ##### YES/NO (1 byte) | Nonce+1 (32 bytes) | AES symmetric key (32 bytes) | HMAC symmetric key (32 bytes)
    Add_Row_To_Client_Data_Table(
        "SERVER", serverIP, serverPort, serialized_serv_pub_key, loginReply[33:65], loginReply[65:97], loginReply[1:33]
    )
    print "Logged In"
    print clientDataTable


    # Start listening on the socket on a separate thread
    # thread.start_new_thread(keep_listening, ())
