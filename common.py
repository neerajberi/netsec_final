from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives import padding as Symmetric_Padding
from cryptography.hazmat.primitives.asymmetric import padding as Asymmetric_Padding

# Grab bytes
def Extract_Bytes(bytes, start, end):
    return extracted_bytes

# Asymmetric Encryption
def Asymmetric_Encrypt(Clear_Text, Pub_Key):
    return Ciph_Text

# Asymmetric Decryption
def Asymmetric_Decrypt(Ciph_Text, Pri_Key):
    return Clear_Text

# Hash_Signing_PriKey
def Get_Signed_Hash(data, Pri_Key):
    return Signed_Hash

# Signature Verification
def Verify_Signature(data, Signed_Hash, Pub_Key):
    return Boolean (Return True if signatures match, else False)

# Symmetric Encryption
def Symmetric_Encrypt(Clear_Text, AES_Key):
    return Ciph_Text, IV

# Symmetric Decryption
def Symmetric_Decrypt(Ciph_Text, AES_Key, IV):
    return Clear_Text

# Calculate HMAC
def get_HMAC(data, HKey):
    return HMAC

# Verify HMAC
def Verify_HMAC(data, HMAC, Hkey):
    return Boolean (Return True if signatures match, else False)
