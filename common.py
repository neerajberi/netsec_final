import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives import padding as Symmetric_Padding
from cryptography.hazmat.primitives.asymmetric import padding as Asymmetric_Padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

# Grab bytes
#def Extract_Bytes(bytes, start, end):
#    return extracted_bytes

# Asymmetric Encryption
def Asymmetric_Encrypt(Pub_Key, Clear_Text):
   serializedPubKey = serialization.load_pem_public_key(Pub_Key, backend=default_backend())
   if isinstance(serializedPubKey, rsa.RSAPublicKey) != True:
       raise RuntimeError ("Invalid Public key file")
   Ciph_Text = serializedPubKey.encrypt(
       Clear_Text,padding.OAEP(
           mgf=padding.MGF1(algorithm=hashes.SHA1()),
           algorithm=hashes.SHA1(),
           label=None
       )
   )
   return Ciph_Text

# Asymmetric Decryption
def Asymmetric_Decrypt(Pri_Key, Ciph_Text):
   serializedPrivateKey = serialization.load_pem_private_key(Pri_Key,password=None,backend=default_backend())
   if isinstance(serializedPrivateKey,rsa.RSAPrivateKey) != True:
       raise RuntimeError ("Invalid Private key file")
   Clear_Text = serializedPrivateKey.decrypt(
       Ciph_Text,
       padding.OAEP(
           mgf = padding.MGF1(algorithm=hashes.SHA1()),
           algorithm=hashes.SHA1(),
           label=None
       )
   )
   return Clear_Text

# Hash_Signing_PriKey
#def Get_Signed_Hash(data, Pri_Key):
#   return Signed_Hash

# Signature Verification
#def Verify_Signature(data, Signed_Hash, Pub_Key):
#   return Boolean (Return True if signatures match, else False)

# Symmetric Encryption
def Symmetric_Encrypt(Clear_Text, AES_Key):
   backend = default_backend()
   iv = os.urandom(16)
   cipher = Cipher(algorithms.AES(AES_Key), modes.CBC(iv), backend=backend)
   encryptor = cipher.encryptor()
   Ciph_Text = encryptor.update(Clear_Text) + encryptor.finalize()
   return Ciph_Text, iv

# Symmetric Decryption
def Symmetric_Decrypt(Ciph_Text, AES_Key, IV):
   backend = default_backend()
   cipher = Cipher(algorithms.AES(AES_Key), modes.CBC(IV),backend=backend)
   decryptor = cipher.decryptor()
   Clear_Text = decryptor.update(Ciph_Text) + decryptor.finalize()
   return Clear_Text

# Calculate HMAC
#def get_HMAC(data, HKey):
#   return HMAC

# Verify HMAC
#def Verify_HMAC(data, HMAC, Hkey):
#   return Boolean (Return True if signatures match, else False)
