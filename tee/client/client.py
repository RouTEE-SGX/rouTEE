# if need to install python3
# https://somjang.tistory.com/entry/PythonUbuntu%EC%97%90-Python-37-%EC%84%A4%EC%B9%98%ED%95%98%EA%B8%B0

import socket
from datetime import datetime
import csv
import sys
# python crypto library example: https://blog.naver.com/chandong83/221886840586
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
import multiprocessing
from multiprocessing import Pool
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

# sockets for multiprocessing
client_sockets = []
for i in range(multiprocessing.cpu_count()):
    s = socket.socket()
    s.connect((SERVER_IP, SERVER_PORT))
    client_sockets.append(s)


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
        f = open(SCRIPTS_PATH+fileName, 'r')
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
    cmdNumber = file_len(SCRIPTS_PATH+fileName)
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
            print("  result:", result)

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
                with open(RESULTS_PATH+"addUserResult", "at") as f1:
                    f1.write(repr(elapsedMicrosec) + "\n")
            elif command[0][0] == 't' and command[0][2] == 'j':
                depositReqCount = depositReqCount + 1
                depositReqTimeSum = depositReqTimeSum + elapsedMicrosec
                with open(RESULTS_PATH+"addDepositResult", "at") as f1:
                    f1.write(repr(elapsedMicrosec) + "\n")
            elif command[0][0] == 'r':
                depositTxCount = depositTxCount + 1
                depositTxTimeSum = depositTxTimeSum + elapsedMicrosec
                with open(RESULTS_PATH+"depositTxResult", "at") as f1:
                    f1.write(repr(elapsedMicrosec) + "\n")
            elif command[0][0] == 't' and command[0][2] == 'm':
                paymentCount = paymentCount + 1
                paymentTimeSum = paymentTimeSum + elapsedMicrosec
                with open(RESULTS_PATH+"paymentResult", "at") as f1:
                    f1.write(repr(elapsedMicrosec) + "\n")
            elif command[0][0] == 't' and command[0][2] == 'l':
                settleReqCount = settleReqCount + 1
                settleReqTimeSum = settleReqTimeSum + elapsedMicrosec
                with open(RESULTS_PATH+"settlementResult", "at") as f1:
                    f1.write(repr(elapsedMicrosec) + "\n")
            elif command[0][0] == 't' and command[0][2] == 'q':
                updateSPVCount = updateSPVCount + 1
                updateSPVTimeSum = updateSPVTimeSum + elapsedMicrosec
                with open(RESULTS_PATH+"updateBoundaryResult", "at") as f1:
                    f1.write(repr(elapsedMicrosec) + "\n")

    totalElapsed = datetime.now() - totalStartTime
    # print("run script elapsed time:", totalElapsed, "\n")
    print("elapsed time:", totalElapsed)
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
        # print("response decryption success")
        # print("result:", result.decode())
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
        with open(KEYS_PATH+"private_key_{}.pem".format(user), "rb") as f:
            sk = RSA.import_key(f.read())
        with open(KEYS_PATH+"public_key_{}.pem".format(user), "rb") as f:
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

# send signed & encrypted operation messages to RouTEE
def send_lines(command):
    # if FILE_NAME[:6] != 'signed':
    #     return

    try:
        f = open(SCRIPTS_PATH+command, 'r')
        rdr = csv.reader(f)
    except:
        print("there are no proper script; try again")
        cmd = input("input command: ")
        send_lines(cmd)
        return

    for command in rdr:
        # ignore '\n'
        if len(command) == 0:
            continue
        client_socket.sendall(bytes.fromhex(command[0]))
        data_ = client_socket.recv(1024)
        # see results
        # mac = bytes(data_[:MAC_SIZE])
        # nonce = bytes(data_[MAC_SIZE:MAC_SIZE+NONCE_SIZE])
        # cipher_data = bytes(data_[MAC_SIZE+NONCE_SIZE:])
        # key = bytes([0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf])
        # aad = bytes([0])
        # result = dec(key, aad, nonce, cipher_data, mac)
        # if result != b'SUCCESS':
        #     print("data: ", result)
        #     # return

def send_line(line):
    # allocate socket
    process_num = int(multiprocessing.current_process().name.split('-')[-1])
    my_socket = client_sockets[process_num-1]

    # send/receive data to/from RouTEE
    my_socket.sendall(bytes.fromhex(line))
    data_ = my_socket.recv(1024)

def send_line_measure_latency(line):
    # allocate socket
    process_num = int(multiprocessing.current_process().name.split('-')[-1])
    my_socket = client_sockets[process_num-1]

    # send/receive data to/from RouTEE & measure latency
    startTime = datetime.now()
    my_socket.sendall(bytes.fromhex(line))
    data_ = my_socket.recv(1024)
    elapsed = datetime.now() - startTime
    return elapsed

# send command lines parallelly
def send_line_parallel(script, do_measure_latency=False):
    try:
        commands = open(SCRIPTS_PATH+script, 'r')
        rdr = csv.reader(commands)
    except:
        print("there are no proper script; try again")
        cmd = input("input command: ")
        send_line_parallel(cmd)
        return

    # send commands parallelly
    latencies = []
    startTime = datetime.now()
    if do_measure_latency:
        latencies = pool.map(send_line_measure_latency, commands, 1)
        # for latency in latencies:
        #     print("latency:", latency.total_seconds())
        #     print("latency:", int(latency.total_seconds()*1000000), "microsec")
    else:
        pool.map(send_line, commands, 1)
    elapsed = datetime.now() - startTime
    print("elapsed time:", elapsed)
    return latencies

def avg_(A: list, clipping=(0, 0)):
    if len(A[clipping[0]:]) != 0:
        A = A[clipping[0]:]
    if len(A[:(len(A) - clipping[1])]) != 0:
        A = A[:(len(A) - clipping[1])]
    return sum(A) / len(A)

def med_(A: list, clipping=(0, 0)):
    if len(A[clipping[0]:]) != 0:
        A = A[clipping[0]:]
    if len(A[:(len(A) - clipping[1])]) != 0:
        A = A[:(len(A) - clipping[1])]
    len_ = len(A)
    if len_ % 2 == 0:
        tmp_A = sorted(A)
        return (tmp_A[len_ // 2 - 1] + tmp_A[len_ // 2]) / 2
    else:
        return sorted(A)[len_ // 2]

def min_(A: list, clipping=(0, 0)):
    if len(A[clipping[0]:]) != 0:
        A = A[clipping[0]:]
    if len(A[:(len(A) - clipping[1])]) != 0:
        A = A[:(len(A) - clipping[1])]
    return sorted(A)[0]

def max_(A: list, clipping=(0, 0)):
    if len(A[clipping[0]:]) != 0:
        A = A[clipping[0]:]
    if len(A[:(len(A) - clipping[1])]) != 0:
        A = A[:(len(A) - clipping[1])]
    return sorted(A, reverse=True)[0]

def nin_(A: list, clipping=(0, 0)):
    if len(A[clipping[0]:]) != 0:
        A = A[clipping[0]:]
    if len(A[:(len(A) - clipping[1])]) != 0:
        A = A[:(len(A) - clipping[1])]
    idx = int(len(A) * 0.99)
    if (idx == (len(A) - 1)) and (idx > 0):
        idx -= 1
    return sorted(A)[idx]

if __name__ == "__main__":
    print("start")
    THREAD_COUNT = multiprocessing.cpu_count() - 1 # minus one is for host.py
    pool = Pool(THREAD_COUNT)
    print("thread count:", pool._processes)
    # send_line_parallel("signedAddUser_5")
    # send_line_parallel("signedPayment_5_100000_1")

    # if there is sys.argv input from command line, run a single script
    # if len(sys.argv) == 2:
    #     scriptName = sys.argv[1]
    #     runScript(scriptName)
    #     sys.exit()

    SEND_SIGNED = False
    if len(sys.argv) == 2:
        if sys.argv[1] == 'signed':
            SEND_SIGNED = True

    while (True):
        try:
            command = input("\ninput command: ")
        except EOFError:
            break

        if command[:6] == 'signed':
            SEND_SIGNED = True
        else:
            SEND_SIGNED = False

        if SEND_SIGNED:
            # send_lines(command)
            send_line_parallel(command)
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
            # print("result:", data)
            elapsedMicrosec = elapsed.seconds * 1000000 + elapsed.microseconds
            elapsedMillisec = elapsedMicrosec / 1000.0
            elapsedSec = elapsedMillisec / 1000.0
            print("elapsed:", elapsedMicrosec, "microsec /", elapsedMillisec, "millisec /", elapsedSec, "sec\n")

    # close socket
    client_socket.close()
