from tqdm import tqdm
import random
import sys
from bitcoinaddress import Address, Key, Wallet
import os.path
import csv
import codecs
import hashlib
from datetime import datetime
from pathlib import Path
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
import multiprocessing
from multiprocessing import Pool

# ex. USER_ID_LEN = '03' -> user000, user001, ...
USER_ID_LEN = '07'
# print epoch to show script generation progress
PRINT_EPOCH = 1000

def base58(address_hex):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    b58_string = ''
    # Get the number of leading zeros
    # leading_zeros = len(address_hex) - len(address_hex.lstrip('0'))
    leading_zeros = 0
    # Convert hex to decimal
    address_int = int(address_hex, 16)
    # Append digits to the start of string
    while address_int > 0:
        digit = address_int % 58
        digit_char = alphabet[digit]
        b58_string = digit_char + b58_string
        address_int //= 58
    # Add ‘1’ for each 2 leading zeros
    ones = leading_zeros // 2
    for one in range(ones):
        b58_string = '1' + b58_string
    return b58_string

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

def executeCommand(command):
    # print(command)
    isForDeposit = False
    isAddDeposit = False

    # secure command option
    if command[0] == 't':
        isSecure = True
        # OP_GET_READY_FOR_DEPOSIT
        if command[2] == 'v':
            isForDeposit = True
        if command[2] == 'j':
            isAddDeposit = True
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

    # encryption using RSA
    try:
        with open("../key/private_key_{}.pem".format(user), "rb") as f:
            sk = RSA.import_key(f.read())
        with open("../key/public_key_{}.pem".format(user), "rb") as f:
            vk = RSA.import_key(f.read())
    except:
        print("no user key")
        exit()

    if isForDeposit:
        pubkey = (vk.n).to_bytes(384, 'little')
        pubkey_hex = pubkey.hex()
        # print(pubkey_hex)
        message = command + b" " + pubkey
    elif isAddDeposit:
        # ADD_DEPOSIT do not require signature
        message = command
    else:
        hash = SHA256.new(command)
        # print(hash.digest().hex())
        sig = pkcs1_15.new(sk).sign(hash)
        message = command + b" " + sig

        try:
            pkcs1_15.new(vk).verify(hash, sig)
        except:
            print("bad signature")
            exit()

    if isSecure:
        # execute secure_command
        return secure_command(message, user)
    else:
        return message

def secure_command(message, sessionID):
    # encrypt command with (hardcoded) symmetric key
    key = bytes([0x0,0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf])
    aad = bytes([0])
    nonce = gen_random_nonce()
    # print("plain text command:", command[2:])
    enc_cmd, mac = enc(key, aad, nonce, message)
    secure_cmd = mac + nonce + enc_cmd
    secure_cmd = ("p {} ".format(sessionID)).encode('utf-8') + secure_cmd
    return secure_cmd

# Generate ECC private key
def makeNewUsers(keyNumber):
    Path("../key").mkdir(parents=True, exist_ok=True)
    with open("scriptAddress", "wt") as f:
        for i in tqdm(range(keyNumber)):
            
            userID = "user" + format(i, USER_ID_LEN)
            if os.path.exists("../key/private_key_{}.pem".format(userID)):
                # print("this user already exist, just skip")
                continue

            # generate key pair to make signature for operation message to RouTEE
            private_key = RSA.generate(3072)
            public_key = private_key.publickey()

            with open("../key/private_key_{}.pem".format(userID), "wb") as f1:
                f1.write(private_key.export_key('PEM'))
            with open("../key/public_key_{}.pem".format(userID), "wb") as f2:
                f2.write(public_key.export_key('PEM'))

def makeNewAddresses_thread(num):
    if (num) % PRINT_EPOCH == 0:
        print("generate", num, "addresses", end="\r")
    # generate bitcoin address as a user address in RouTEE
    wallet = Wallet(testnet=True)
    # print("user address:", wallet.address.__dict__['testnet'].pubaddr1)
    return "{}".format(wallet.address.__dict__['testnet'].pubaddr1)

# Generate bitcoin address
def makeNewAddresses(addressNumber):
    addresses = pool.map(makeNewAddresses_thread, range(addressNumber+1)[1:], 1)

    # write addresses to the file
    with open("scriptAddress", "wt") as fscript:
        for address in addresses:
            fscript.write(address+"\n")

# generate AddUser commands
def makeNewAccounts_thread(params):
    settle_address = params[0]
    num = params[1]
    if (num) % PRINT_EPOCH == 0:
        print("generate", num, "accounts", end="\r")
    userID = "user" + format(0, USER_ID_LEN) # for easy experiment
    command = "t v {} {}".format(settle_address, userID)
    signedCommand = executeCommand(command).hex()
    return command, signedCommand

# Script for generating rouTEE accounts
def makeNewAccounts(accountNumber):
    if not os.path.exists("scriptAddress"):
        print("ERROR: execute makeNewAddresses first\n")
        return
    
    if not os.path.exists("../key/private_key_{}.pem".format("user" + format(0, USER_ID_LEN))):
        print("ERROR: execute makeNewUsers first\n")
        return

    # get addresses from the file
    addressFile = open("scriptAddress", 'r')
    rdr = csv.reader(addressFile)
    params = []
    cnt = 0
    for address in rdr:
        cnt += 1
        params.append((address[0], cnt))
        if cnt == accountNumber:
            break
    
    if len(params) != accountNumber:
        print("ERROR: there is not enough addresses, execute makeNewAddresses first")
        return

    # parallelly generate plain & signed command
    commands = pool.map(makeNewAccounts_thread, params, 1)

    # write commands to files
    with open("scriptAddUser_{}".format(accountNumber), "wt") as fscript, open("signedAddUser_{}".format(accountNumber), "w") as fsigned:
        for cmd in commands:
            fscript.write(cmd[0]+"\n")
            fsigned.write(cmd[1]+"\n")

def getReadyForDeposit_thread(params):
    # parse params
    beneficiary_index = params[0]
    num = params[1]
    if num % PRINT_EPOCH == 0:
        print("generate", num, "requests", end="\r")
    userID = "user" + format(0, USER_ID_LEN) # for easy experiment

    # generate & sign command
    command = "t j {} {}".format(beneficiary_index, userID)
    signedCommand = executeCommand(command).hex()

    return command, signedCommand

# Script for generating deposit requests
def getReadyForDeposit(userNumber, requestNumber):
    if not os.path.exists("scriptAddress"):
        print("ERROR: execute makeNewAddresses first\n")
        return

    # collect params for threads
    params = []
    for i in range(requestNumber):
        user_index = random.randint(0, userNumber - 1)
        params.append((user_index, i+1))

    # parallelly generate plain & signed command
    commands = pool.map(getReadyForDeposit_thread, params, 1)

    # write commands to files
    with open("scriptManager_{}_{}".format(userNumber, requestNumber), "wt") as fscript, open("signedManager_{}_{}".format(userNumber, requestNumber), "w") as fsigned:
        for cmd in commands:
            fscript.write(cmd[0]+"\n")
            fsigned.write(cmd[1]+"\n")

# Script for managing deposit transactions
# Should be used only for testing
def dealWithDepositTxs(accountNumber):
    if not os.path.exists("scriptAddress"):
        print("ERROR: execute makeNewAddresses first\n")
        return
    addressFile = open("scriptAddress", 'r')
    rdr = csv.reader(addressFile)
    count = 0
    with open("scriptDepositTx", "wt") as fscript, open("signedDepositTx", "w") as fsigned:
        for address in tqdm(rdr):
            user_address = address[0]
            userID = "user" + format(rdr.line_num - 1, USER_ID_LEN)         
            command = "r {} 0 100000000 100 {}".format(user_address, userID)
            fscript.write(command + "\n")

            signedCommand = executeCommand(command)
            # fsigned.write(signedCommand)
            fsigned.write(signedCommand.hex())
            fsigned.write('\n')

            count = count + 1
            if count == accountNumber:
                break

# generate Payment commands
def doMultihopPayments_thread(params):
    # print("params:", params)
    sender_index = params[0]
    receiver_indexes = params[1]
    num = params[2]
    if num % PRINT_EPOCH == 0:
        print("generate", num, "payments", end="\r")
    batchSize = len(receiver_indexes)
    senderID = "user" + format(0, USER_ID_LEN) # for easy experiment
    command = "t m {} {} ".format(sender_index, batchSize)  
    for i in range(batchSize):
        command += "{} 100 ".format(receiver_indexes[i])
    command += "10 {}".format(senderID)

    signedCommand = executeCommand(command).hex()

    return command, signedCommand

# Script for payments among users
def doMultihopPayments(addressNumber, paymentNumber, batchSize):
    if not os.path.exists("scriptAddress"):
        print("ERROR: execute makeNewAddresses first\n")
        return
    if not os.path.exists("../key/private_key_{}.pem".format("user" + format(0, USER_ID_LEN))):
        print("ERROR: execute makeNewUsers first\n")
        return
    if addressNumber < 2:
        print("ERROR: you need at least 2 addresses to appear")
        return

    addressFile = open("scriptAddress", 'r')
    rdr = csv.reader(addressFile)

    # get addresses from file
    address_list = []
    cnt = 0
    for address in rdr:
        address_list.append(address[0])
        cnt += 1
        if cnt == addressNumber:
            break
    
    if len(address_list) != addressNumber:
        print("ERROR: there is not enough addresses, execute makeNewAddresses first")
        return

    params = []
    for i in range(paymentNumber):
        sender_index = random.randint(0, addressNumber - 1)
        receiver_indexes = []
        while True:
            receiver_index = random.randint(0, addressNumber - 1)
            if (sender_index != receiver_index) and (receiver_index not in receiver_indexes):
                receiver_indexes.append(receiver_index)
            if len(receiver_indexes) == batchSize:
                break
        params.append((sender_index, receiver_indexes, i+1))

    # parallelly generate plain & signed command
    commands = pool.map(doMultihopPayments_thread, params, 1)

    # write commands to files
    with open("scriptPayment_{}_{}_{}".format(addressNumber, paymentNumber, batchSize), "wt") as fscript, open("signedPayment_{}_{}_{}".format(addressNumber, paymentNumber, batchSize), "w") as fsigned:
        for cmd in commands:
            fscript.write(cmd[0]+"\n")
            fsigned.write(cmd[1]+"\n")

def settleBalanceRequest_thread(params):
    # parse params
    user_index = params[0]
    num = params[1]
    if num % PRINT_EPOCH == 0:
        print("generate", num, "settle requests", end="\r")
    userID = "user" + format(0, USER_ID_LEN) # for easy experiment

    # generate & sign command
    command = "t l {} 100 10 {}".format(user_index, userID)
    signedCommand = executeCommand(command).hex()

    return command, signedCommand

# Script for generating settle requests
def settleBalanceRequest(userNumber, settleRequestNumber):
    if not os.path.exists("scriptAddress"):
        print("ERROR: execute makeNewAddresses first\n")
        return

    # collect params for threads
    params = []
    for i in range(settleRequestNumber):
        user_index = random.randint(0, userNumber - 1)
        params.append((user_index, i+1))

    # parallelly generate plain & signed command
    commands = pool.map(settleBalanceRequest_thread, params, 1)

    # write commands to files
    with open("scriptSettle_{}_{}".format(userNumber, settleRequestNumber), "wt") as fscript, open("signedSettle_{}_{}".format(userNumber, settleRequestNumber), "w") as fsigned:
        for cmd in commands:
            fscript.write(cmd[0]+"\n")
            fsigned.write(cmd[1]+"\n")

# generate Payment commands
def updateBoundary_thread(params):
    # parse params
    user_index = params[0]
    block_number = params[1]
    block_hash = params[2]
    num = params[3]
    if num % PRINT_EPOCH == 0:
        print("generate", num, "updates", end="\r")
    userID = "user" + format(0, USER_ID_LEN) # for easy experiment

    # generate & sign command
    command = "t q {} {} {} {}".format(user_index, block_number, block_hash, userID)
    signedCommand = executeCommand(command).hex()

    return command, signedCommand

# Script for updating boundary block number
def updateBoundary(addressNumber, updateNumber, maxBlockNumber):
    if not os.path.exists("scriptAddress"):
        print("ERROR: execute makeNewAddresses first\n")
        return

    addressFile = open("scriptAddress", 'r')
    rdr = csv.reader(addressFile)

    # generate temp block hashes
    block_hashes = []
    BITCOIN_HEADER_HASH_LEN = 32
    for i in range(maxBlockNumber+1):
        block_hash = str(i).zfill(BITCOIN_HEADER_HASH_LEN*2)
        block_hashes.append(block_hash)

    # collect params for threads
    params = []
    for i in range(updateNumber):
        user_index = random.randint(0, addressNumber - 1)
        block_number = random.randint(0, maxBlockNumber)
        block_hash = block_hashes[block_number]
        params.append((user_index, block_number, block_hash, i+1))

    # parallelly generate plain & signed command
    commands = pool.map(updateBoundary_thread, params, 1)

    # write commands to files
    with open("scriptUpdate_{}_{}_{}".format(addressNumber, updateNumber, maxBlockNumber), "wt") as fscript, open("signedUpdate_{}_{}_{}".format(addressNumber, updateNumber, maxBlockNumber), "w") as fsigned:
        for cmd in commands:
            fscript.write(cmd[0]+"\n")
            fsigned.write(cmd[1]+"\n")

if __name__ == '__main__':
    # set multithreading pool
    THREAD_COUNT = multiprocessing.cpu_count()
    pool = Pool(THREAD_COUNT)
    print("multithread count:", THREAD_COUNT)

    # if there is sys.argv input from command line, run a single script
    if len(sys.argv) >= 2:
        command = int(sys.argv[1])
    else:
        command = eval(input("which script do you want to make (0: makeNewUsers / 1: makeNewAddresses / 2: makeNewAccounts / 3: getReadyForDeposit & dealWithDepositTxs / 4: doMultihopPayments / 5: settleBalanceRequest / 6: updateBoundary / 7: default)): "))
    
    startTime = datetime.now()
    if command == 0:
        if len(sys.argv) >= 2:
            userNumber = int(sys.argv[2])
            scriptName = sys.argv[3]
        else:
            userNumber = eval(input("how many users to generate: "))
            scriptName = "scriptUser"
        makeNewUsers(userNumber)
    elif command == 1:
        if len(sys.argv) >= 2:
            addressNumber = int(sys.argv[2])
            scriptName = sys.argv[3]
        else:
            addressNumber = eval(input("how many bitcoin addresses to generate: "))
            scriptName = "scriptAddress"
        makeNewAddresses(addressNumber)

    elif command == 2:
        if len(sys.argv) >= 2:
            accountNumber = int(sys.argv[2])
            scriptName = sys.argv[3]
        else:
            accountNumber = eval(input("how many routee accounts to generate: "))
            scriptName = "scriptAccount"
        makeNewAccounts(accountNumber)

    elif command == 3:
        if len(sys.argv) >= 2:
            userNumber = int(sys.argv[2])
            requestNumber = int(sys.argv[3])
            scriptName = sys.argv[4]
        else:
            userNumber = eval(input("how many users to appear: "))
            requestNumber = eval(input("how many manager addresses to generate: "))
            scriptName = "scriptDeposit"
        getReadyForDeposit(userNumber, requestNumber)
        # dealWithDepositTxs(depositNumber)

    elif command == 4:
        if len(sys.argv) >= 2:
            paymentNumber = int(sys.argv[2])
            batchSize = int(sys.argv[3])
            scriptName = sys.argv[4]
        else:
            addressNumber = eval(input("how many addresses to appear: "))
            paymentNumber = eval(input("how many rouTEE payments to generate: "))
            batchSize = eval(input("how many transactions per payment request (batch size): "))
            scriptName = "scriptPayment"
        doMultihopPayments(addressNumber, paymentNumber, batchSize)

    elif command == 5:
        if len(sys.argv) >= 2:
            userNumber = int(sys.argv[2])
            settleRequestNumber = int(sys.argv[3])
            scriptName = sys.argv[4]
        else:
            userNumber = eval(input("how many users to appear: "))
            settleRequestNumber = eval(input("how many rouTEE settle requests to generate: "))
            scriptName = "scriptSettle"
        settleBalanceRequest(userNumber, settleRequestNumber)

    elif command == 6:
        if len(sys.argv) >= 2:
            addressNumber = int(sys.argv[2])
            updateNumber = int(sys.argv[3])
            maxBlockNumber = int(sys.argv[4])
            scriptName = sys.argv[5]
        else:
            addressNumber = eval(input("how many addresses to appear: "))
            updateNumber = eval(input("how many rouTEE updates to generate: "))
            maxBlockNumber = eval(input("max block number in RouTEE: "))
            scriptName = "scriptUpdate"
        updateBoundary(addressNumber, updateNumber, maxBlockNumber)

    elif command == 7:
        accountNumber = eval(input("how many routee accounts to generate: "))
        depositNumber = eval(input("how many routee deposits to generate: "))
        paymentNumber = eval(input("how many rouTEE payments to generate: "))
        batchSize = eval(input("how many transactions per payment request (batch size): "))
        settleRequestNumber = eval(input("how many rouTEE settle balance requests to generate: "))
        updateSPVNumber = eval(input("how many rouTEE SPV block updates to generate: "))
        # makeNewAddresses(accountNumber)
        makeNewAccounts(accountNumber)
        getReadyForDeposit(depositNumber)
        dealWithDepositTxs(depositNumber)
        doMultihopPayments(paymentNumber, batchSize)
        settleBalanceRequest(settleRequestNumber)
        updateBoundary(updateSPVNumber)

        scriptName = "scriptForAll"

    print("make script [", scriptName, "] Done")
    elapsed = datetime.now() - startTime
    print("elapsed time:", elapsed)
