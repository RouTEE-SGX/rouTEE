# if need to install python3
# https://somjang.tistory.com/entry/PythonUbuntu%EC%97%90-Python-37-%EC%84%A4%EC%B9%98%ED%95%98%EA%B8%B0

import socket
from datetime import datetime
import csv
import sys
import base64
# python crypto library example: https://blog.naver.com/chandong83/221886840586
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
import hashlib

# rouTEE IP address
SERVER_IP = "127.0.0.1"
PORT = 7327

# open socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# connect to the server
client_socket.connect((SERVER_IP, PORT))

# command scripts for rouTEE
SCRIPTSPATH = "scripts/"

# encryption/decryption setting
KEY_SIZE = 16 # bytes
MAC_SIZE = 16 # bytes
NONCE_SIZE = 12 # bytes

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

# get file length
def file_len(fileName):
    with open(fileName) as f:
        for i, l in enumerate(f):
            pass
    return i + 1

# execute the script for rouTEE
def runScript(fileName):
    # print("run script", fileName, "\n")

    try:
        f = open(SCRIPTSPATH+fileName, 'r')
        rdr = csv.reader(f)
    except:
        print("there are no proper script; try again")
        cmd = input("input command: ")
        runScript(cmd)
        return

    # command count
    addUserCount = 0
    depositReqCount = 0
    depositTxCount = 0
    paymentCount = 0
    settleReqCount = 0
    updateSPVCount = 0

    # command execution time sum (microsec)
    addUserTimeSum = 0
    depositReqTimeSum = 0
    depositTxTimeSum = 0
    paymentTimeSum = 0
    settleReqTimeSum = 0
    updateSPVTimeSum = 0

    totalStartTime = datetime.now()
    elapsedTimeSum = 0
    cnt = 0
    cmdNumber = file_len(SCRIPTSPATH+fileName)
    printEpoch = cmdNumber/100
    for command in rdr:
        # ignore '\n'
        if len(command) == 0:
            continue
        cnt = cnt + 1

        result, elapsed = executeCommand(command[0])

        if result is None:
            print("something went wrong!\n")
        else:
            # print(result)

            # calculate elapsed time
            elapsedMicrosec = elapsed.seconds * 1000000 + elapsed.microseconds
            elapsedMillisec = elapsedMicrosec / 1000.0
            elapsedSec = elapsedMillisec / 1000.0
            elapsedTimeSum = elapsedTimeSum + elapsedMicrosec

            # print results
            if cnt%printEpoch == 0:
                # print("script cmd (", cnt, "/", cmdNumber, ") :", command[0])
                # print("elapsed time:", elapsed)
                # print('Received:', data.decode())
                # print("elapsed:", elapsedMicrosec, "microsec /", elapsedMillisec, "millisec /", elapsedSec, "sec\n")
                pass

            # logging execution time info
            if command[0][0] == 't' and command[0][2] == 'v':
                addUserCount = addUserCount + 1
                addUserTimeSum = addUserTimeSum + elapsedMicrosec
                with open("experiment/addUserResult", "at") as f1:
                    f1.write(repr(elapsedMicrosec) + "\n")
            elif command[0][0] == 't' and command[0][2] == 'j':
                depositReqCount = depositReqCount + 1
                depositReqTimeSum = depositReqTimeSum + elapsedMicrosec
                with open("experiment/depositReqResult", "at") as f1:
                    f1.write(repr(elapsedMicrosec) + "\n")
            elif command[0][0] == 'r':
                depositTxCount = depositTxCount + 1
                depositTxTimeSum = depositTxTimeSum + elapsedMicrosec
                with open("experiment/depositTxResult", "at") as f1:
                    f1.write(repr(elapsedMicrosec) + "\n")
            elif command[0][0] == 't' and command[0][2] == 'm':
                paymentCount = paymentCount + 1
                paymentTimeSum = paymentTimeSum + elapsedMicrosec
                with open("experiment/paymentResult", "at") as f1:
                    f1.write(repr(elapsedMicrosec) + "\n")
            elif command[0][0] == 't' and command[0][2] == 'l':
                settleReqCount = settleReqCount + 1
                settleReqTimeSum = settleReqTimeSum + elapsedMicrosec
                with open("experiment/settleReqResult", "at") as f1:
                    f1.write(repr(elapsedMicrosec) + "\n")
            elif command[0][0] == 't' and command[0][2] == 'q':
                updateSPVCount = updateSPVCount + 1
                updateSPVTimeSum = updateSPVTimeSum + elapsedMicrosec
                with open("experiment/updateSPVResult", "at") as f1:
                    f1.write(repr(elapsedMicrosec) + "\n")

    totalElapsed = datetime.now() - totalStartTime
    # print("run script elapsed time:", totalElapsed, "\n")
    print("run script elapsed time:", totalElapsed)
    # print("elapsed time sum:", elapsedTimeSum, "ms")

    # try:
    #     # print("payment count:", paymentCount, "/ payment execution time:", paymentTimeSum, "( avg time:", paymentTimeSum/paymentCount, "ms )")
    # except:
    #     # print("payment count:", 0, "/ payment execution time:", 0, "( avg time:", 0, "ms )")
    # try:
    #     # print("settle count:", settleCount, "/ settle execution time:", settleTimeSum, "( avg time:", settleCount/settleTimeSum, "ms )")
    # except:
    #     # print("settle count:", 0, "/ settle execution time:", 0, "( avg time:", 0, "ms )")
    # try:
    #     # print("create channel count:", createChannelCount, "/ create channel execution time:", createChannelTimeSum, "( avg time:", createChannelTimeSum/createChannelCount, "ms )")
    # except:
    #     # print("create channel count:", 0, "/ create channel execution time:", 0, "( avg time:", 0, "ms )")

    # print("")
    return


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
        #print("response decryption success")
        #print("result:", result.decode())
        return result.decode(), elapsed
    else:
        #print("ERROR: decryption failed, (maybe) plain response msg:", data.decode())
        return None, elapsed 
    

def executeCommand(command):
    # print(command)
    isForDeposit = False

    # secure command option
    if command[0] == 't':
        isSecure = True
        # OP_GET_READY_FOR_DEPOSIT
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
        with open("./key/private_key_{}.pem".format(user), "rb") as f:
            sk = RSA.import_key(f.read())
        with open("./key/public_key_{}.pem".format(user), "rb") as f:
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

    return data.decode(), elapsed

    # print('Received:', data.decode())

    # print elapsed time
    # elapsedMicrosec = elapsed.seconds * 1000000 + elapsed.microseconds
    # elapsedMillisec = elapsedMicrosec / 1000.0
    # elapsedSec = elapsedMillisec / 1000.0
    # print("elapsed:", elapsedMicrosec, "microsec /", elapsedMillisec, "millisec /", elapsedSec, "sec\n")


def send_line(command):
    # if FILE_NAME[:6] != 'signed':
    #     return
    client_socket.sendall(bytes.fromhex(command))
    data_ = client_socket.recv(1024)


if __name__ == "__main__":
    print("start")

    # if there is sys.argv input from command line, run a single script
    # if len(sys.argv) == 2:
    #     scriptName = sys.argv[1]
    #     runScript(scriptName)
    #     sys.exit()

    if len(sys.argv) == 2:
        if sys.argv[1] == 'signed':
            SEND_SIGNED = True

    while (True):
        # command = input("input command: ")
        try:
            command = input()
        except EOFError:
            break

        if SEND_SIGNED:
            send_line(command)
            continue

        if len(command) == 0:
            # ignore '\n'
            # print("")
            continue

        if command[0] == 's':
            # execute script
            runScript(command)
            continue

        data, elapsed = executeCommand(command)

        if data is None:
            print("something went wrong! try again\n")
            
        else:
            # print(data)
            elapsedMicrosec = elapsed.seconds * 1000000 + elapsed.microseconds
            elapsedMillisec = elapsedMicrosec / 1000.0
            elapsedSec = elapsedMillisec / 1000.0
            print("elapsed:", elapsedMicrosec, "microsec /", elapsedMillisec, "millisec /", elapsedSec, "sec\n")

    # close socket
    client_socket.close()
