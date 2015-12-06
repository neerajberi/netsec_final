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

# testing server user verification
def Test_Verify_User():
    if chatserver.Verify_User('jack', '4098'):
        if not chatserver.Verify_User('jack', '4099'):
            print("user verification          : SUCCESS")
            return
    print("user verification          : FAILED")

Test_Sym("1234567890123456789012345678901234567890123456789012345678901234")
Test_Sym("12345678901234567890123456789012345678901234567")
Test_Asym("1234567890123456789012345678901234567890123456789012345678901234")
Test_Asym("12345678901234567890123456789012345678901234567")
Test_Verify_User()
Test_Challenge()
