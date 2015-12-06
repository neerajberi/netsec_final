from os import urandom
import common

# testing symmetric encryption/decryption with input equal to blocksize
try:
    sym_input     = "1234567890123456789012345678901234567890123456789012345678901234"
    sym_aes_key   = urandom(32) # 256 bit AES key
    sym_ciph, iv  = common.Symmetric_Encrypt(sym_input, sym_aes_key)
    sym_plaintext = common.Symmetric_Decrypt(sym_ciph,  sym_aes_key, iv)
    if sym_input == sym_plaintext:
        print("1 : symmetric encrypt/decrypt : SUCCESS")
    else:
        print("1 : symmetric encrypt/decrypt : FAILED - unequal")
except:
    print("1 : symmetric encrypt/decrypt : FAILED - exception")

# testing symmetric encryption/decryption with input not equal to blocksize
try:
    sym_input     = "this string is not equal to a block length of 512"
    sym_aes_key   = urandom(32) # 256 bit AES key
    sym_ciph, iv_notblock  = common.Symmetric_Encrypt(sym_input, sym_aes_key)
    sym_plaintext = common.Symmetric_Decrypt(sym_ciph,  sym_aes_key, iv_notblock)
    if sym_input == sym_plaintext:
        print("2 : symmetric encrypt/decrypt : SUCCESS")
    else:
        print("2 : symmetric encrypt/decrypt : FAILED - unequal")
except:
    print("2 : symmetric encrypt/decrypt : FAILED - exception")

# common.Asymmetric_Encrypt(Pub_Key, Clear_Text)
# common.Asymmetric_Decrypt(Pri_Key, Ciph_Text)
