INSTALLATION:
We have included a default server keypair in the server_keypair folder. It is recommended that you replace these keys with your own generated keys. Make sure that you name them server_private_key.pem and server_public_key.pem respectively. 

The client needs the following files in this directory structure:
/common.py
/chatclient.py
/server_keypair/server_public_key.pem

The server needs the following files in this directory structure:
/common.py
/chatserver.py
/server_keypair/server_public_key.pem
/server_keypair/server_private_key.pem

The client should NOT have access to the server private key.

USAGE:
chatserver: "python chatserver.py"
  note: the default port for the server is 9090
  example command:
    python chatserver.py
chatclient: "python chatclient.py -sip <serverip> -sp <serverport>"
  example command:
    python chatclient.py -sip localhost -sp 9090

USER CREDENTIALS:
jack : 4098
sape : 4139
sap1 : 4132
sap2 : 4136
sap3 : 4134

