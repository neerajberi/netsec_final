from os import urandom
import common, chatserver

# testing symmetric encryption/decryption
def Test_Sym(input_string):
    try:
        sym_aes_key   = urandom(32) # 256 bit AES key
        sym_ciph, iv_notblock  = common.Symmetric_Encrypt(input_string, sym_aes_key)
        sym_plaintext = common.Symmetric_Decrypt(sym_ciph,  sym_aes_key, iv_notblock)
        if input_string == sym_plaintext:
            print("symmetric encrypt/decrypt  : SUCCESS")
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
            print("asymmetric encrypt/decrypt : SUCCESS")
        else:
            print("asymmetric encrypt/decrypt : FAILED - unequal")
    except:
        print("asymmetric encrypt/decrypt : FAILED - exception")

# testing challenge/response
def Test_Challenge():
    hash_output, hash_input = common.Create_Challenge()
    attempt = common.Solve_Challenge(hash_output, hash_input)
    if common.Verify_Challenge_Solution(attempt, hash_output):
        print("challenge/response         : SUCCESS")
    else:
        print("challenge/response         : FAILED")

# testing server user verification (this needs to be more general or something)
def Test_Verify_User():
    if chatserver.Verify_User('jack', '4098'):
        if not chatserver.Verify_User('jack', '4099'):
            print("user verification          : SUCCESS")
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
        print("Get_Message_ID             : SUCCESS")
    else:
        print("Get_Message_ID             : FAILURE")
    if common.Get_Message_ID('user_login') == 4:
        print("Get_Message_ID             : SUCCESS")
    else:
        print("Get_Message_ID             : FAILURE")
    if common.Get_Message_Name(0b00000011) == 'challenge_result':
        print("Get_Message_Name           : SUCCESS")
    else:
        print("Get_Message_Name           : FAILURE")
    if common.Get_Message_Name(3) == 'challenge_result':
        print("Get_Message_Name           : SUCCESS")
    else:
        print("Get_Message_Name           : FAILURE")

Test_Sym("1234567890123456789012345678901234567890123456789012345678901234")
Test_Sym("12345678901234567890123456789012345678901234567")
Test_Asym("1234567890123456789012345678901234567890123456789012345678901234")
Test_Asym("12345678901234567890123456789012345678901234567")
Test_Verify_User()
Test_Message_ID_Functions()
Test_Challenge()
