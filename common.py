# python 3.5

import os, time, sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives import padding as Symmetric_Padding
from cryptography.hazmat.primitives.asymmetric import padding as Asymmetric_Padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

# creates a challenge. returns the first 32 bits of the hash and the first 112
# bits of the input. that is 112/128 of the input. meaning the challenged has to
# guess 16 bits
def Create_Challenge():
    hash_input = os.urandom(16)
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(hash_input)
    hash_output = digest.finalize()
    return hash_output[:4], hash_input[:14]

# solves a challenge, returning all 128 bits of the input which hashed to the
# given output. THERE ARE FASTER WAYS TO DO THIS, BUT IT DOESN'T MATTER IN OUR
# CASE.
def Solve_Challenge(hash_output, hash_input):
    while True:
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        attempt = os.urandom(2)
        digest.update(hash_input + attempt)
        attempted_solution = digest.finalize()
        if attempted_solution[:4] == hash_output:
            return hash_input + attempt

# verifies a given attempt to solve a hash problem.
def Verify_Challenge_Solution(attempt, hash_output):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(attempt)
    attempted_solution = digest.finalize()
    if attempted_solution[:4] == hash_output:
        return True
    else:
        return False

# Serializes the private key bytes
def Serialize_Pri_Key(key_bytes):
    serialized_pri_key = serialization.load_pem_private_key(
        key_bytes,
        password=None,
        backend=default_backend())
    if isinstance(serialized_pri_key, rsa.RSAPrivateKey) != True:
        raise RuntimeError ("Invalid Private key file")
    else:
        return serialized_pri_key

# Serializes the public key bytes
def Serialize_Pub_Key(key_bytes):
    serialized_pub_key = serialization.load_pem_public_key(
        key_bytes,
        backend=default_backend())
    if isinstance(serialized_pub_key, rsa.RSAPublicKey) != True:
        raise RuntimeError ("Invalid Public key file")
    else:
        return serialized_pub_key

# Padding for Symmetric Encryption
def Padding_For_Symm_Encryption(in_clear_string, block_size):
    paddingBytesNeeded = block_size - len(in_clear_string) % block_size
    if paddingBytesNeeded < 2:
        paddingBytesNeeded += block_size
    paddedStringSize = len(in_clear_string) + paddingBytesNeeded
    paddedString = in_clear_string.zfill(paddedStringSize)
    paddedStringList = list(paddedString)
    if paddingBytesNeeded < 10:
        paddedStringList[1] = str(paddingBytesNeeded)
    else:
        paddingBytesNeededList = list(str(paddingBytesNeeded))
        paddedStringList[0] = paddingBytesNeededList[0]
        paddedStringList[1] = paddingBytesNeededList[1]
    paddedString = "".join(paddedStringList)
    return paddedString

# Remove Padding from AES decrypted data
def Remove_Padding(padded_string):
    padded_string_list = list(padded_string[0:2])
    padded_bytes = "".join(padded_string_list)
    padded_bytes = int(padded_bytes)
    original_plain_text = padded_string[padded_bytes:]
    return original_plain_text

# Asymmetric Encryption
def Asymmetric_Encrypt(pub_key, clear_text):
    serialized_pub_key = Serialize_Pub_Key(pub_key)
    return serialized_pub_key.encrypt(
        clear_text,
        Asymmetric_Padding.OAEP(
            mgf=Asymmetric_Padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

# Asymmetric Decryption
def Asymmetric_Decrypt(pri_key, ciph_text):
    serialized_pri_key = Serialize_Pri_Key(pri_key)
    return serialized_pri_key.decrypt(
        ciph_text,
        Asymmetric_Padding.OAEP(
            mgf=Asymmetric_Padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

# Hash_Signing_PriKey
def Get_Signed_Hash(data, pri_key):
    signer = pri_key.signer(
        Asymmetric_Padding.PSS(
            mgf=Asymmetric_Padding.MGF1(hashes.SHA256()),
            salt_length=Asymmetric_Padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    signer.update(data)
    return signer.finalize()

# Signature Verification
def Verify_Signature(data, signed_hash, pub_key):
    verifier = pub_key.verifier(
        signed_hash,
        Asymmetric_Padding.PSS(
            mgf=Asymmetric_Padding.MGF1(hashes.SHA256()),
            salt_length=Asymmetric_Padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    verifier.update(data)
    try:
        verifier.verify()
        return True
    except:
        return False

# Symmetric Encryption
def Symmetric_Encrypt(clear_text, aes_key):
   block_size = 16
   paddedString = Padding_For_Symm_Encryption(clear_text, block_size)
   backend = default_backend()
   iv = os.urandom(16)
   cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=backend)
   encryptor = cipher.encryptor()
   ciph_text = encryptor.update(paddedString) + encryptor.finalize()
   return ciph_text, iv

# Symmetric Decryption
def Symmetric_Decrypt(ciph_text, aes_key, iv):
   backend = default_backend()
   cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv),backend=backend)
   decryptor = cipher.decryptor()
   paddedClearText = decryptor.update(ciph_text) + decryptor.finalize()
   Clear_Text = Remove_Padding(paddedClearText)
   return Clear_Text

# Calculate HMAC
#def get_HMAC(data, HKey):
#   return HMAC

# Verify HMAC
#def Verify_HMAC(data, HMAC, Hkey):
#   return Boolean (Return True if signatures match, else False)
