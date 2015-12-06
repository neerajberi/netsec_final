# chat server
# python 3.5

import sys, socket, getopt, select, common

# server private/public key pair
serv_pri_key_path = "server_keypair/server_private_key.pem"
serv_pub_key_path = "server_keypair/server_public_key.pem"
with open(serv_pri_key_path, "rb") as key_file:
    serv_pri_key = key_file.read()
with open(serv_pub_key_path, "rb") as key_file:
    serv_pub_key = key_file.read()

# list of users and their associated passwords (IGNORING THE SALT FOR NOW)
# username | salted-password | salt
user_passes = {
    'jack': common.Hash_This('4098'),
    'sape': common.Hash_This('4139'),
    'sap1': common.Hash_This('4132'),
    'sap2': common.Hash_This('4136'),
    'sap3': common.Hash_This('4134')
}

# verifies a user
def Verify_User(username, password):
    if user_passes[username] == common.Hash_This(password):
        return True
    else:
        return False

# list of challenged users
# IP | Port | Can send pass?

# list of currently connected users
# username | IP | Port | Public Key | Shared AES key | Shared HKey | Nonce
