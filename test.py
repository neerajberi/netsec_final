from os import urandom
import common

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

Test_Sym("1234567890123456789012345678901234567890123456789012345678901234")
Test_Sym("12345678901234567890123456789012345678901234567")
Test_Asym("1234567890123456789012345678901234567890123456789012345678901234")
Test_Asym("12345678901234567890123456789012345678901234567")
