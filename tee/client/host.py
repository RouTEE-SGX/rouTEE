import socket
from datetime import datetime
import csv
import sys, os
import time
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from routee_configs import *


# open socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# connect to the server
try:
    client_socket.connect((SERVER_IP, SERVER_PORT))
    print("successfully connect to RouTEE")
except Exception as e:
    print("connect failed: start RouTEE first or set SERVER_IP and SERVER_PORT correctly")
    print("  current SERVER_IP:", SERVER_IP)
    print("  current SERVER_PORT:", SERVER_PORT)
    sys.exit()


# print byte array
def print_hex_bytes(name, byte_array):
    # print('{} len[{}]: '.format(name, len(byte_array)), end='')
    for idx, c in enumerate(byte_array):
        # print("{:02x}".format(int(c)), end='')
        pass
    # print("")


# generate random key
def gen_random_key():
    return get_random_bytes(KEY_SIZE)


# generate random nonce (= Initialization Vector, IV)
def gen_random_nonce():
    return get_random_bytes(NONCE_SIZE)


# AES-GCM encryption
def enc(key, aad, nonce, plain_data):

    # AES-GCM cipher
    cipher = AES.new(key, AES.MODE_GCM, nonce)

    # add AAD (Additional Associated Data)
    # cipher.update(aad)

    # encrypt plain data & get MAC tag
    cipher_data = cipher.encrypt(plain_data)
    mac = cipher.digest()
    return cipher_data, mac


# AES-GCM decryption
def dec(key, aad, nonce, cipher_data, mac):

    # AES128-GCM cipher
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    
    # add AAD (Additional Associated Data)
    # cipher.update(aad)

    try:
        # try decrypt
        plain_data = cipher.decrypt_and_verify(cipher_data, mac)
        return plain_data
    except ValueError:
        # ERROR: wrong MAC tag, data is contaminated
        return None


def secure_command(message, sessionID):
    # encrypt command with (hardcoded) symmetric key
    key = bytes([0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf])
    aad = bytes([0])
    nonce = gen_random_nonce()
    # print("plain text command:", command[2:])
    enc_cmd, mac = enc(key, aad, nonce, message)
    secure_cmd = mac + nonce + enc_cmd
    secure_cmd = ("p {} ".format(sessionID)).encode('utf-8') + secure_cmd

    #print(secure_cmd)

    # send command to server
    startTime = datetime.now()
    client_socket.sendall(secure_cmd)

    # get response from server
    data = client_socket.recv(1024)
    elapsed = datetime.now() - startTime

    # calculate elapsed time
    elapsedMicrosec = elapsed.seconds * 1000000 + elapsed.microseconds
    elapsedMillisec = elapsedMicrosec / 1000.0
    elapsedSec = elapsedMillisec / 1000.0

    # print("elapsed:", elapsed)
    # print("elapsed:", elapsedMicrosec, "microsec /", elapsedMillisec, "millisec /", elapsedSec, "sec\n")

    # decrypt response from rouTEE
    mac = bytes(data[:MAC_SIZE])
    nonce = bytes(data[MAC_SIZE:MAC_SIZE+NONCE_SIZE])
    cipher_data = bytes(data[MAC_SIZE+NONCE_SIZE:])
    result = dec(key, aad, nonce, cipher_data, mac)

    # check the result
    if result is not None:
        print("response decryption success")
        print("result:", result.decode())
        return result.decode(), elapsed
    else:
        print("ERROR: decryption failed, (maybe) plain response msg:", data.decode())
        return None, elapsed 


def executeCommand(command):
    # print(command)
    isForDeposit = False

    # secure command option
    if command[0] == 't':
        isSecure = True
        # ADD_USER operation (OP_GET_READY_FOR_DEPOSIT)
        if command[2] == 'v':
            isForDeposit = True
    else:
        isSecure = False
        if command[0] == 'r':
            isForDeposit = True

    split_command = command.split(" ")
    #print(split_command)

    # commnad's last string means message sender 
    user = split_command[-1]

    if isSecure:
        # remove 't ' from command
        command = " ".join(split_command[1:-1])
    else:
        command = " ".join(split_command[:-1])

    # encode command
    command = command.encode('utf-8')

    try:
        with open(KEY_PATH+"private_key_{}.pem".format(user), "rb") as f:
            sk = RSA.import_key(f.read())
        with open(KEY_PATH+"public_key_{}.pem".format(user), "rb") as f:
            vk = RSA.import_key(f.read())
    except:
        print("no user key")
        exit()

    if isForDeposit:
        pubkey = (vk.n).to_bytes(384, 'little')
        # pubkey_hex = pubkey.hex()
        # print(pubkey_hex)
        message = command + b" " + pubkey
    else:
        hash = SHA256.new(command)
        # print(hash.digest().hex())
        sig = pkcs1_15.new(sk).sign(hash)
        message = command + b" " + sig

    if isSecure:
        # execute secure_command
        # print("secure command")
        return secure_command(message, user)
        # continue

    # send message to server
    startTime = datetime.now()
    # send command + signature to routee
    client_socket.sendall(message)

    # get response from server
    data = client_socket.recv(1024)
    elapsed = datetime.now() - startTime
    # print(elapsed)

    print('Received:', data.decode())

    return data.decode(), elapsed

    # print elapsed time
    # elapsedMicrosec = elapsed.seconds * 1000000 + elapsed.microseconds
    # elapsedMillisec = elapsedMicrosec / 1000.0
    # elapsedSec = elapsedMillisec / 1000.0
    # print("elapsed:", elapsedMicrosec, "microsec /", elapsedMillisec, "millisec /", elapsedSec, "sec\n")


if __name__ == "__main__":

    if len(sys.argv) == 3:
        round_interval_sec = int(sys.argv[1])
        round_num = int(sys.argv[2])
    else:
        print("ERROR: input round_interval and round_num")
        sys.exit()

    # check if host's key exists
    hostID = "user" + format(0, USER_ID_LEN)
    if not os.path.exists(KEY_PATH+"private_key_{}.pem".format(hostID)):
        print("ERROR: there is no host key, execute makeNewAddresses first or set USER_ID_LEN correctly")
        print("  host ID:", hostID)
        sys.exit()

    print("start")
    print("  round interval:", round_interval_sec, "sec")
    print("  round num to run:", round_num)

    round_interval = round_interval_sec * 1000000000 # sec to nanosec
    current_round = 0
    executed_time = time.time_ns() - 0.9 * round_interval
    while current_round < round_num:
        current_time = time.time_ns()
        if current_time > executed_time + round_interval:
            # measure real interval
            measured_interval = current_time - executed_time
            # update executed time
            executed_time = current_time

            # do the job
            # executeCommand("a user0000000") # ping
            current_round += 1
            print("\nRound", current_round)
            executeCommand("x " + hostID) # process round
            print("measured interval:", measured_interval/1000000000, "sec\n")
    
    print("finish")
