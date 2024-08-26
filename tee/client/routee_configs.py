import os

# rouTEE IP address
SERVER_IP = "172.17.0.3"
SERVER_PORT = 7557

# name of address list
ADDR_LIST_FILE_NAME = "addressList"

# paths for script, key
SCRIPTS_PATH = "scripts/"
KEYS_PATH = "keys/"
RESULTS_PATH = "results/"
# generate dirs if not exist
if not os.path.exists(SCRIPTS_PATH):
    os.makedirs(SCRIPTS_PATH)
if not os.path.exists(KEYS_PATH):
    os.makedirs(KEYS_PATH)
if not os.path.exists(RESULTS_PATH):
    os.makedirs(RESULTS_PATH)

# ex. USER_ID_LEN = '03' -> user000, user001, ...
USER_ID_LEN = '07'

# generating key is time consuming, just use one key to generate signature
USE_SINGLE_KEY = False

# encryption/decryption setting
KEY_SIZE = 16 # bytes
MAC_SIZE = 16 # bytes
NONCE_SIZE = 12 # bytes

BITCOIN_HEADER_HASH_LEN = 32
