import os

# rouTEE IP address
SERVER_IP = "172.17.0.3"
SERVER_PORT = 7557

# name of address list
ADDR_LIST_FILE_NAME = "addressList"

# paths for script, key
SCRIPTS_PATH = "scripts/"
KEY_PATH = "keys/"
# generate dirs if not exist
if not os.path.exists(SCRIPTS_PATH):
    os.makedirs(SCRIPTS_PATH)
    print("gen path:", SCRIPTS_PATH)
if not os.path.exists(KEY_PATH):
    os.makedirs(KEY_PATH)
    print("gen path:", KEY_PATH)

# ex. USER_ID_LEN = '03' -> user000, user001, ...
USER_ID_LEN = '07'

# encryption/decryption setting
KEY_SIZE = 16 # bytes
MAC_SIZE = 16 # bytes
NONCE_SIZE = 12 # bytes

BITCOIN_HEADER_HASH_LEN = 32
