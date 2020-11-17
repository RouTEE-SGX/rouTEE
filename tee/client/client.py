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
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS

import bitcoin_crypto
import ecdsa
import hashlib

# rouTEE IP address
SERVER_IP = "127.0.0.1"
PORT = 7223

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

    f = open(SCRIPTSPATH+fileName, 'r')
    rdr = csv.reader(f)

    # command count
    paymentCount = 0
    settleCount = 0
    createChannelCount = 0

    # command execution time sum (microsec)
    paymentTimeSum = 0
    settleTimeSum = 0
    createChannelTimeSum = 0

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

        # send cmd & measure execution time
        startTime = datetime.now()
        if command[0][0] == 't':
            # send encrypted cmd & get encrypted response and decrypt it
            secure_command(command[0])
            continue
        else:
            # send plain cmd & get plain response
            client_socket.sendall(command[0].encode())
            data = client_socket.recv(1024)
            # check the result
            if data.decode() != "SUCCESS":
                # print("ERROR: command failed\n")
                # print("error msg:", data.decode())
                return
        elapsed = datetime.now() - startTime

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
        if command[0][0] == 'j':
            createChannelCount = createChannelCount + 1
            createChannelTimeSum = createChannelTimeSum + elapsedMicrosec
        elif command[0][0] == 'l':
            settleCount = settleCount + 1
            settleTimeSum = settleTimeSum + elapsedMicrosec
        elif command[0][0] == 'm':
            paymentCount = paymentCount + 1
            paymentTimeSum = paymentTimeSum + elapsedMicrosec

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

    print(secure_cmd)

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
    else:
        print("ERROR: decryption failed, (maybe) plain response msg:", data.decode())
    print()

if __name__ == "__main__":
    print("start")

    # if there is sys.argv input from command line, run a single script
    if len(sys.argv) == 2:
        scriptName = sys.argv[1]
        runScript(scriptName)
        sys.exit()

    while (True):
        command = input("input command: ")
        if len(command) == 0:
            # ignore '\n'
            # print("")
            continue
        
        if command[0] == 's':
            # execute script
            runScript(command)
            continue

        isForDeposit = False

        # secure command option
        if command[0] == 't':
            isSecure = True
            # OP_GET_READY_FOR_DEPOSIT
            if command[2] == 'j':
                isForDeposit = True
        else:
            isSecure = False


        # # message: byte encoding of command
        # message = command.encode('utf-8')

        # # generate ECDSA signature
        # private_key = ECC.import_key(open('./key/private_key_host.pem').read())
        # h = SHA256.new(message)
        # signer = DSS.new(private_key, 'fips-186-3')
        # signature = signer.sign(h)

        # # verify the signature
        # public_key = ECC.import_key(open('./key/public_key_host.pem').read())
        # h = SHA256.new(message)
        # verifier = DSS.new(public_key, 'fips-186-3')
        # try:
        #     verifier.verify(h, signature)
        #     print("The message is authentic.")
        # except ValueError:
        #     print("The message is not authentic.")

        # r = signature[:signer._order_bytes]
        # s = signature[signer._order_bytes:]

        # # print signature
        # print(r, s)

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

        # encryption using ECDSA
        with open("./key/private_key_{}.pem".format(user)) as f:
            sk = ecdsa.SigningKey.from_pem(f.read())
        with open("./key/public_key_{}.pem".format(user)) as f:
            vk = ecdsa.VerifyingKey.from_pem(f.read())    

        if isForDeposit:
            pubkey = b"\x04" + vk.pubkey.point.x().to_bytes(32, 'big') + vk.pubkey.point.y().to_bytes(32, 'big')
            print(pubkey)
            message = command + b" " + pubkey

        else:
            sig = sk.sign(command, hashfunc=hashlib.sha256)

            try:
                vk.verify(sig, command, hashfunc=hashlib.sha256)
                print("good signature")
            except:
                print("bad signature")

            message = command + b" " + sig

        if isSecure:
            # execute secure_command
            print("secure command")
            secure_command(message, user)
            continue

        # send message to server
        startTime = datetime.now()
        # send command + signature to routee
        client_socket.sendall(message)

        # get response from server
        data = client_socket.recv(1024)
        elapsed = datetime.now() - startTime
        # print(elapsed)
        print('Received:', data.decode())

        # print elapsed time
        elapsedMicrosec = elapsed.seconds * 1000000 + elapsed.microseconds
        elapsedMillisec = elapsedMicrosec / 1000.0
        elapsedSec = elapsedMillisec / 1000.0
        # print("elapsed:", elapsedMicrosec, "microsec /", elapsedMillisec, "millisec /", elapsedSec, "sec\n")
    
    # close socket
    client_socket.close()
