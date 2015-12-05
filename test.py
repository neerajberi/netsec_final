from os import urandom
import common

sym_input     = "1234567890123456789012345678901234567890123456789012345678901234"
sym_aes_key   = urandom(32) # 256 bit AES key
sym_ciph, iv  = common.Symmetric_Encrypt(sym_input, sym_aes_key)
sym_plaintext = common.Symmetric_Decrypt(sym_ciph,  sym_aes_key, iv)
if sym_input == sym_plaintext:
    print("symmetric encrypt success")
else:
    print("symmetric encrypt failed")

# common.Asymmetric_Encrypt(Pub_Key, Clear_Text)
# common.Asymmetric_Decrypt(Pri_Key, Ciph_Text)
