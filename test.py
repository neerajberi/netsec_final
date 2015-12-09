from os import urandom
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import common, binascii#, chatserver

# testing symmetric encryption/decryption
def Test_Sym(input_string):
    try:
        sym_aes_key   = urandom(32) # 256 bit AES key
        sym_ciph, iv_notblock  = common.Symmetric_Encrypt(input_string, sym_aes_key)
        sym_plaintext = common.Symmetric_Decrypt(sym_ciph,  sym_aes_key, iv_notblock)
        if input_string == sym_plaintext:
            print("symmetric encrypt/decrypt  : success")
        else:
            print("symmetric encrypt/decrypt  : FAILED - unequal")
    except:
        print("symmetric encrypt/decrypt  : FAILED - exception")

# testing asymmetric encryption/decryption
def Test_Asym(input_string):
    try:
        pri_key_path = "server_keypair/server_private_key.pem"
        pub_key_path = "server_keypair/server_public_key.pem"
        with open(pri_key_path, "rb") as key_file:
            pri_key = key_file.read()
        with open(pub_key_path, "rb") as key_file:
            pub_key = key_file.read()
        asym_ciph      = common.Asymmetric_Encrypt(pub_key, input_string)
        asym_plaintext = common.Asymmetric_Decrypt(pri_key, asym_ciph)
        if input_string == asym_plaintext:
            print("asymmetric encrypt/decrypt : success")
        else:
            print("asymmetric encrypt/decrypt : FAILED - unequal")
    except:
        print("asymmetric encrypt/decrypt : FAILED - exception")

# testing challenge/response
def Test_Challenge():
    hash_output, hash_input = common.Create_Challenge()
    attempt = common.Solve_Challenge(hash_output, hash_input)
    if common.Verify_Challenge_Solution(attempt, hash_output):
        print("challenge/response         : success")
    else:
        print("challenge/response         : FAILED")

# testing server user verification (this needs to be more general or something)
def Test_Verify_User():
    if chatserver.Verify_User('jack', '4098'):
        if not chatserver.Verify_User('jack', '4099'):
            print("user verification          : success")
            return
    print("user verification          : FAILED")
    #print(Is_User_Challenged('129.0.0.1', '9090'))
    #print(Is_User_Challenged('129.0.0.1', '9091'))
    #print(Is_User_Challenged('129.0.0.2', '9090'))
    #print(Can_User_Auth('129.0.0.1', '9090'))
    #print(Can_User_Auth('129.0.0.1', '9091'))
    #print(Can_User_Auth('129.0.0.2', '9090'))

def Test_Message_ID_Functions():
    if common.Get_Message_ID('A2_to_A1_ack') == 0b00001011:
        print("Get_Message_ID             : success")
    else:
        print("Get_Message_ID             : FAILURE")
    if common.Get_Message_ID('user_login') == 4:
        print("Get_Message_ID             : success")
    else:
        print("Get_Message_ID             : FAILURE")
    if common.Get_Message_Name(0b00000011) == 'challenge_result':
        print("Get_Message_Name           : success")
    else:
        print("Get_Message_Name           : FAILURE")
    if common.Get_Message_Name(3) == 'challenge_result':
        print("Get_Message_Name           : success")
    else:
        print("Get_Message_Name           : FAILURE")

def Test_Serialization():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend())
    serialized_pri_key = common.Serialize_Pri_Key(private_key)
    #print serialized_pri_key
    # I guess this isnt working because the private key OBJECT has data other
    # than that which is stored in serialized version.
    if (private_key == common.Deserialize_Pri_Key(serialized_pri_key)):
        print "Private Key Serialization  : success"
    else:
        print "Private Key Serialization  : FAILURE"
    public_key = private_key.public_key()
    serialized_pub_key = common.Serialize_Pub_Key(public_key)
    #print serialized_pub_key
    # I guess this isnt working because the public key OBJECT has data other
    # than that which is stored in serialized version.
    if (public_key == common.Deserialize_Pub_Key(serialized_pub_key)):
        print "Public Key Serialization   : success"
    else:
        print "Public Key Serialization   : FAILURE"

def Test_Verify_Hmac():
    message = urandom(1212)
    sharedHkey = urandom(32)
    hmac_Calculated = common.get_HMAC(message,sharedHkey)
    print "hmac_Calculated = %s" % hmac_Calculated
    if common.Verify_HMAC(message, hmac_Calculated, sharedHkey):
        print "HMAC verification          : success"
    else:
        print "HMAC verification          : FAILURE"
    #print "message = %s" % message
    #print "length HMAC = %s" % len(hmac_Calculated)

def Test_Get_4byte_IP_Address():
    IP = raw_input("Enter IP in string\n+> ")
    fourbyteIP = common.Get_4byte_IP_Address(IP)
    stringIP = common.Get_String_IP_from_4byte_IP(fourbyteIP)
    print "Four byte IP as chars = " + fourbyteIP
    print "Four byte IP as hex   = " + binascii.hexlify(fourbyteIP)
    print "stringIP              = " + stringIP
    if IP == stringIP:
        print "4byte IP conversion        : success"
    else:
        print "4byte IP conversion        : FAILURE"
    return

def Test_Get_2byte_Port_Number():
    intPort = input("Enter an integer smaller than 65536\n+> ")
    twoBytePort = common.Get_2byte_Port_Number(intPort)
    print "Two byte Port as chars = " + twoBytePort
    port = common.Get_Integer_Port_from_2byte_Port(twoBytePort)
    print "Two byte Port as hex   = " + binascii.hexlify(twoBytePort)
    port = common.Get_Integer_Port_from_2byte_Port(twoBytePort)
    print "Integer port           = %s" % port
    if intPort == port:
        print "2byte port conversion      : success"
    else:
        print "2byte port conversion      : FAILURE"
    return


#Test_Sym("1234567890123456789012345678901234567890123456789012345678901234")
#Test_Sym("12345678901234567890123456789012345678901234567")
#Test_Asym("1234567890123456789012345678901234567890123456789012345678901234")
#Test_Asym("12345678901234567890123456789012345678901234567")
#Test_Verify_User()
#Test_Message_ID_Functions()
#Test_Serialization()
#Test_Challenge()
#Test_Verify_Hmac()
Test_Get_4byte_IP_Address()
Test_Get_2byte_Port_Number()
