from os import urandom
import common

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

try:
    sym_notblock_input     = "this string is not equal to a block length of 512"
    print sym_notblock_input
    sym_notblock_aes_key   = urandom(32) # 256 bit AES key
    sym_notblock_ciph, iv_notblock  = common.Symmetric_Encrypt(sym_notblock_input, sym_notblock_aes_key)
    print sym_notblock_ciph
    sym_notblock_plaintext = common.Symmetric_Decrypt(sym_notblock_ciph,  sym_notblock_aes_key, iv_notblock)
    print sym_notblock_plaintext
    if sym_notblock_input == sym_notblock_plaintext:
        print("3 : symmetric encrypt/decrypt : SUCCESS")
    else:
        print("3 : symmetric encrypt/decrypt : FAILED -0 unequal")
except:
    print("3 : symmetric encrypt/decrypt : FAILED - exception")

# common.Asymmetric_Encrypt(Pub_Key, Clear_Text)
# common.Asymmetric_Decrypt(Pri_Key, Ciph_Text)
