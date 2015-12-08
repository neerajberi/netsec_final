# python 3.5

import os, time, sys, binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives import padding as Symmetric_Padding
from cryptography.hazmat.primitives.asymmetric import padding as Asymmetric_Padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding

def Increment_Nonce(nonce_input):
    hex_nonce = binascii.hexlify(nonce_input)
    int_nonce = int(hex_nonce,16)
    inc_nonce = int_nonce + 1
    hex_inc_nonce = hex(inc_nonce)
    inc_nonce_bytes = binascii.unhexlify((hex_inc_nonce[2:])[:-1])
    return inc_nonce_bytes

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

# Serializes a private key instance
def Serialize_Pri_Key(key_instance):
    serialized_pri_key = key_instance.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption())
    return serialized_pri_key

# Serializes a public key instance
def Serialize_Pub_Key(key_instance):
    serialized_pub_key = key_instance.public_bytes(
       encoding=serialization.Encoding.PEM,
       format=serialization.PublicFormat.SubjectPublicKeyInfo)
    return serialized_pub_key

# Deserializes the private key bytes
def Deserialize_Pri_Key(key_bytes):
    deserialized_pri_key = serialization.load_pem_private_key(
        key_bytes,
        password=None,
        backend=default_backend())
    if isinstance(deserialized_pri_key, rsa.RSAPrivateKey) != True:
        raise RuntimeError ("Invalid Private key file")
    else:
        return deserialized_pri_key

# Deserializes the public key bytes
def Deserialize_Pub_Key(key_bytes):
    deserialized_pub_key = serialization.load_pem_public_key(
        key_bytes,
        backend=default_backend())
    if isinstance(deserialized_pub_key, rsa.RSAPublicKey) != True:
        raise RuntimeError ("Invalid Public key file")
    else:
        return deserialized_pub_key

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
    deserialized_pub_key = Deserialize_Pub_Key(pub_key)
    return deserialized_pub_key.encrypt(
        clear_text,
        Asymmetric_Padding.OAEP(
            mgf=Asymmetric_Padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

# Asymmetric Decryption
def Asymmetric_Decrypt(pri_key, ciph_text):
    deserialized_pri_key = Deserialize_Pri_Key(pri_key)
    return deserialized_pri_key.decrypt(
        ciph_text,
        Asymmetric_Padding.OAEP(
            mgf=Asymmetric_Padding.MGF1(algorithm=hashes.SHA1()),
            algorithm=hashes.SHA1(),
            label=None
        )
    )

# Hash_Signing_PriKey
def Get_Signed_Hash(data, pri_key):
    deserialized_pri_key = Deserialize_Pri_Key(pri_key)
    signer = deserialized_pri_key.signer(
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
    deserialized_pub_key = Deserialize_Pub_Key(pub_key)
    verifier = deserialized_pub_key.verifier(
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

def Hash_This(hash_input):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(hash_input)
    return digest.finalize()

# Calculate HMAC
def get_HMAC(data, HKey):
    h = hmac.HMAC(HKey, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()

# Verify HMAC
def Verify_HMAC(data, recvdhmac, Hkey):
    h = hmac.HMAC(Hkey, hashes.SHA256(), backend=default_backend())
    h.update(data)
    try:
        h.verify(recvdhmac)
        return True
    except:
        return False

# Verify HMAC and return AES decrypted Plain Text using recvData[1:]
# hmac_iv_ciphText should be in this format:
# HMAC 32 bytes | IV 16 bytes | AES encrypted CipherText
def Verify_HMAC_Decrypt_AES(hmac_iv_ciphText, hmac_key, aes_key):
    if not Verify_HMAC(hmac_iv_ciphText[32:], hmac_iv_ciphText[:32], hmac_key):
        print "HMAC verification failed"
        sys.exit()
    return Symmetric_Decrypt(hmac_iv_ciphText[48:], aes_key, hmac_iv_ciphText[32:48])

# AES Encrypt, concatenate with IV, calculate HMAC and return HMAC_IV_CipherText
def AES_Encrypt_Add_HMAC(plain_text, aes_key, hmac_key):
    ciph_text, iv = Symmetric_Encrypt(plain_text, aes_key)
    hmac_input = ''.join([iv, ciph_text])
    hmac_calc = get_HMAC(hmac_input, hmac_key)
    return ''.join([hmac_calc, hmac_input])

# Retrieves the 8-bit message ID associated with a message ref name
def Get_Message_ID(message_name):
    for i in range(0,len(MESSAGE_ID_LIST)):
        if MESSAGE_ID_LIST[i][1] == message_name:
            message_ID = MESSAGE_ID_LIST[i][0]
    return chr(message_ID)

# Retrieves the message ref name associated with a 8-bit message ID
def Get_Message_Name(message_ID):
    message_name = "message_name_not_found"
    message_ID = ord(message_ID)
    for i in range(0,len(MESSAGE_ID_LIST)):
        if MESSAGE_ID_LIST[i][0] == message_ID:
            message_name = MESSAGE_ID_LIST[i][1]
    return message_name

MESSAGE_ID_LIST = [
    [0b00000000, "login_request"],
    [0b00000001, "challenge_to_client"],
    [0b00000010, "challenge_response"],
    [0b00000011, "challenge_result"],

    [0b00000100, "user_login"],
    [0b00000101, "login_reply_from_server"],

    [0b00000110, "client1_request_to_server_for_client2"],
    [0b00000111, "server_sends_info_to_client2"],
    [0b00001000, "client2_reply_to_server"],
    [0b00001001, "server_reply_to_client1"],
    [0b00001010, "A1_to_A2_key_setup"],
    [0b00001011, "A2_to_A1_ack"],
    [0b00001100, "A1_to_A2_send_message"],
    [0b00001101, "A2_to_A1_send_message"],
    [0b00001110, "client_to_server_list_update"],
    [0b00001111, "server_to_client_user_list"],
    [0b00010000, "client_to_server_logout"],
    [0b00010001, "client_to_client_logout"]
]
