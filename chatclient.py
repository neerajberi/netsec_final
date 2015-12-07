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

    serialized_pri_key = common.Serialize_Pri_Key(client_private_key)
    serialized_pub_key = common.Serialize_Pub_Key(client_private_key.public_key())

    username_length = len(username)
    if username_length > 9:
        return False

    # bit0-7: MessageID
    # bit8-167: Signed hash of the encrypted portion |
    # bit0-255: Semi-Unique Nonce |
    #  bit256-511: Publickey of the  Client |
    #    bit512-519: login length(ll) in bytes |
    #      bit520-(520+(8*ll)-1): login |
    #        bit(520+(8*ll)-END: password

    clearText = ''.join([Nonce, serialized_pub_key, str(username_length), username, password])
    cipherText = common.Asymmetric_Encrypt(serialized_serv_pub_key, clearText)
    signedHash = common.Get_Signed_Hash(cipherText, serialized_pri_key)
    messageID = common.Get_Message_ID("user_login")
    sendData = ''.join([str(messageID), signedHash, cipherText])
    sockClient.send(sendData)

    print "sent the user/pass combo!"

    recvData = sockClient.recv(recv_buf)
    if recvData[0:8] != common.Get_Message_ID("login_reply_from_server"):
        print "Invalid message ID"
        sys.exit()
    signedHash = recvData[8:168]
    cipherText = recvData[168:]
    if common.Verify_Signature(cipherText, signedHash, serialized_server_pub_key) == False:
        sys.exit("Server signature verification Failed\nMITM possible\nExiting...")
    clearText = common.Asymmetric_Decrypt(serializedPriKey, cipherText)
    return clearText

#def keep_listening():
#    while True:
#        rawReceivedMessage = sockClient.recv(recv_buf)
#        messageID = rawReceivedMessage[0:7]
#        messageName = common.Get_Message_Name(messageID)
#        if messageName == "challenge_to_client":

# server public key pair
serv_pub_key_path = "server_keypair/server_public_key.pem"
serialized_serv_pub_key = ""
with open(serv_pub_key_path, "rb") as key_file:
    serialized_serv_pub_key = key_file.read()

if __name__ == "__main__":
    recv_buf = 4096
    # Get the command line arguments and use them as IP Address and port number
    argList = sys.argv
    i = 0
    for i in range(0,len(argList)):
        if argList[i] == "-sip":
            serverIP = (argList[i+1])

        if argList[i] == "-sp":
            serverPort = int(argList[i+1])
    sockClient = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sockClient.settimeout(2)

    # connecting to the server
    try:
        sockClient.connect((serverIP, serverPort))
    except:
        print "Something is wrong with the connection."
        print "Check connection parameters."
        print "usage: chatclient.py -sip <IP Address> -sp <Port>"
        sys.exit()
    print "Connected!"

    # Initiate login challenge sequence and exit if failed
    if Request_For_Login() == False:
        sys.exit("Failed Initial Challenge Verification\nCheck challenge hashing module\nExiting...")

    client_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    for i in range(0,5):
        loginReply = Initiate_Login_Sequence(client_private_key)
        if loginReply[0] == True:
            break
        else:
            if i == 4:
                sys.exit("Incorrect username or password\nAll attempts exhausted\nExiting...")
            else:
                print "Incorrect username or password\nPlease try again (Remaining Attempts = %s)" % (4-i)

    # Start listening on the socket on a separate thread
    # thread.start_new_thread(keep_listening, ())
