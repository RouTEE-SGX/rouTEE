from tqdm import tqdm
import random
import sys
from bitcoinaddress import Address, Key, Wallet
import os
import os.path
import csv
from datetime import datetime
from pathlib import Path
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
import multiprocessing
from multiprocessing import Pool
from routee_configs import *

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
        with open(KEYS_PATH+"private_key_{}.pem".format(user), "rb") as f:
            sk = RSA.import_key(f.read())
        with open(KEYS_PATH+"public_key_{}.pem".format(user), "rb") as f:
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


##############################


# generate ECC private key and public key
def makeNewKeys(key_num):
    for i in tqdm(range(key_num)):
        userID = "user" + format(i, USER_ID_LEN)
        if os.path.exists(KEYS_PATH+"private_key_{}.pem".format(userID)):
            # print("this user already exist, just skip")
            continue

        # generate key pair to make signature for operation message to RouTEE
        private_key = RSA.generate(3072)
        public_key = private_key.publickey()

        with open(KEYS_PATH+"private_key_{}.pem".format(userID), "wb") as f1:
            f1.write(private_key.export_key('PEM'))
        with open(KEYS_PATH+"public_key_{}.pem".format(userID), "wb") as f2:
            f2.write(public_key.export_key('PEM'))
    
    print("  -> generated private & public keys")


def makeNewAddresses_thread(num):
    if (num) % PRINT_EPOCH == 0:
        print("generate", num, "addresses", end="\r")
    # generate bitcoin address as a user address in RouTEE
    wallet = Wallet(testnet=True)
    # print("user address:", wallet.address.__dict__['testnet'].pubaddr1)
    return "{}".format(wallet.address.__dict__['testnet'].pubaddr1)


# generate bitcoin address
def makeNewAddresses(addr_num):
    addresses = pool.map(makeNewAddresses_thread, range(addr_num+1)[1:], 1)

    # write addresses to the file
    with open(SCRIPTS_PATH+ADDR_LIST_FILE_NAME, "wt") as fscript:
        for address in addresses:
            fscript.write(address+"\n")

    print("  -> generated", ADDR_LIST_FILE_NAME)


def makeAddUsers_thread(params):
    settle_address = params[0]
    num = params[1]
    if (num) % PRINT_EPOCH == 0:
        print("generate", num, "accounts", end="\r")
    
    if USE_SINGLE_KEY:
        user_index = 0
    else:
        user_index = num

    userID = "user" + format(user_index, USER_ID_LEN)
    command = "t v {} {}".format(settle_address, userID)
    signedCommand = executeCommand(command).hex()
    return command, signedCommand


# generate AddUser commands
def makeAddUsers(accountNumber):
    if not os.path.exists(SCRIPTS_PATH+ADDR_LIST_FILE_NAME):
        print("ERROR: execute makeNewAddresses first\n")
        return
    
    if not os.path.exists(KEYS_PATH+"private_key_{}.pem".format("user" + format(0, USER_ID_LEN))):
        print("ERROR: execute makeNewKeys first\n")
        return

    # get addresses from the file
    addressFile = open(SCRIPTS_PATH+ADDR_LIST_FILE_NAME, 'r')
    rdr = csv.reader(addressFile)
    params = []
    cnt = 0
    for address in rdr:
        params.append((address[0], cnt))
        cnt += 1
        if cnt == accountNumber:
            break
    
    if len(params) != accountNumber:
        print("ERROR: there is not enough addresses, execute makeNewAddresses first")
        return

    # parallelly generate plain & signed command
    commands = pool.map(makeAddUsers_thread, params, 1)

    # write commands to files
    script_name = "scriptAddUser_{}".format(accountNumber)
    signed_script_name = "signedAddUser_{}".format(accountNumber)
    with open(SCRIPTS_PATH+script_name, "wt") as fscript, open(SCRIPTS_PATH+signed_script_name, "w") as fsigned:
        for cmd in commands:
            fscript.write(cmd[0]+"\n")
            fsigned.write(cmd[1]+"\n")
    print("  -> generated", script_name, "&", signed_script_name)


def makeAddDeposits_thread(params):
    # parse params
    beneficiary_index = params[0]
    num = params[1]
    if num % PRINT_EPOCH == 0:
        print("generate", num, "requests", end="\r")
    
    if USE_SINGLE_KEY:
        user_index = 0
    else:
        user_index = beneficiary_index
    userID = "user" + format(user_index, USER_ID_LEN)

    # generate & sign command
    command = "t j {} {}".format(beneficiary_index, userID)
    signedCommand = executeCommand(command).hex()

    return command, signedCommand


# generate AddDeposit commands which return random manager addresses
def makeAddDeposits(userNumber, requestNumber):
    # collect params for threads
    params = []
    for i in range(requestNumber):
        user_index = random.randint(0, userNumber - 1)
        params.append((user_index, i+1))

    # parallelly generate plain & signed command
    commands = pool.map(makeAddDeposits_thread, params, 1)

    # write commands to files
    script_name = "scriptAddDeposit_{}_{}".format(userNumber, requestNumber)
    signed_script_name = "signedAddDeposit_{}_{}".format(userNumber, requestNumber)
    with open(SCRIPTS_PATH+script_name, "wt") as fscript, open(SCRIPTS_PATH+signed_script_name, "w") as fsigned:
        for cmd in commands:
            fscript.write(cmd[0]+"\n")
            fsigned.write(cmd[1]+"\n")
    print("  -> generated", script_name, "&", signed_script_name)


# add user's balance for testing
def dealWithDepositTxs(accountNumber):
    if not os.path.exists(SCRIPTS_PATH+ADDR_LIST_FILE_NAME):
        print("ERROR: execute makeNewAddresses first\n")
        return
    addressFile = open(SCRIPTS_PATH+ADDR_LIST_FILE_NAME, 'r')
    rdr = csv.reader(addressFile)
    count = 0

    script_name = "scriptDepositTx"
    signed_script_name = "signedDepositTx"
    with open(SCRIPTS_PATH+script_name, "wt") as fscript, open(SCRIPTS_PATH+signed_script_name, "w") as fsigned:
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
    print("  -> generated", script_name, "&", signed_script_name)


def makePayments_thread(params):
    # print("params:", params)
    sender_index = params[0]
    receiver_indexes = params[1]
    num = params[2]
    if num % PRINT_EPOCH == 0:
        print("generate", num, "payments", end="\r")
    batchSize = len(receiver_indexes)

    if USE_SINGLE_KEY:
        senderID = "user" + format(0, USER_ID_LEN)
    else:
        senderID = "user" + format(sender_index, USER_ID_LEN)

    command = "t m {} {} ".format(sender_index, batchSize)  
    for i in range(batchSize):
        amount = random.randint(10, 100)
        command += "{} {} ".format(receiver_indexes[i], amount)
    
    fee = random.randint(1, 10)
    command += "{} {}".format(fee, senderID)
    signedCommand = executeCommand(command).hex()

    return command, signedCommand


# generate Payment commands
def makePayments(addressNumber, paymentNumber, batchSize):
    if not os.path.exists(SCRIPTS_PATH+ADDR_LIST_FILE_NAME):
        print("ERROR: execute makeNewAddresses first\n")
        return
    if not os.path.exists(KEYS_PATH+"private_key_{}.pem".format("user" + format(0, USER_ID_LEN))):
        print("ERROR: execute makeNewKeys first\n")
        return
    if addressNumber < 2:
        print("ERROR: you need at least 2 addresses to appear")
        return
    if addressNumber < batchSize+1:
        print("ERROR: you need more addresses than batchSize")
        return

    addressFile = open(SCRIPTS_PATH+ADDR_LIST_FILE_NAME, 'r')
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
    commands = pool.map(makePayments_thread, params, 1)

    # write commands to files
    script_name = "scriptPayment_{}_{}_{}".format(addressNumber, paymentNumber, batchSize)
    signed_script_name = "signedPayment_{}_{}_{}".format(addressNumber, paymentNumber, batchSize)
    with open(SCRIPTS_PATH+script_name, "wt") as fscript, open(SCRIPTS_PATH+signed_script_name, "w") as fsigned:
        for cmd in commands:
            fscript.write(cmd[0]+"\n")
            fsigned.write(cmd[1]+"\n")
    print("  -> generated", script_name, "&", signed_script_name)


def makeSettlements_thread(params):
    # parse params
    user_index = params[0]
    num = params[1]
    if num % PRINT_EPOCH == 0:
        print("generate", num, "settle requests", end="\r")
    
    if USE_SINGLE_KEY:
        userID = "user" + format(0, USER_ID_LEN)
    else:
        userID = "user" + format(user_index, USER_ID_LEN)

    # generate & sign command
    command = "t l {} 100 10 {}".format(user_index, userID)
    signedCommand = executeCommand(command).hex()

    return command, signedCommand


# generate Settlement commands
def makeSettlements(userNumber, settleRequestNumber):
    # collect params for threads
    params = []
    for i in range(settleRequestNumber):
        user_index = random.randint(0, userNumber - 1)
        params.append((user_index, i+1))

    # parallelly generate plain & signed command
    commands = pool.map(makeSettlements_thread, params, 1)

    # write commands to files
    script_name = "scriptSettlement_{}_{}".format(userNumber, settleRequestNumber)
    signed_script_name = "signedSettlement_{}_{}".format(userNumber, settleRequestNumber)
    with open(SCRIPTS_PATH+script_name, "wt") as fscript, open(SCRIPTS_PATH+signed_script_name, "w") as fsigned:
        for cmd in commands:
            fscript.write(cmd[0]+"\n")
            fsigned.write(cmd[1]+"\n")
    print("  -> generated", script_name, "&", signed_script_name)


def makeUpdateBoundaryBlocks_thread(params):
    # parse params
    user_index = params[0]
    block_number = params[1]
    block_hash = params[2]
    num = params[3]
    if num % PRINT_EPOCH == 0:
        print("generate", num, "updates", end="\r")

    if USE_SINGLE_KEY:
        userID = "user" + format(0, USER_ID_LEN)
    else:
        userID = "user" + format(user_index, USER_ID_LEN)

    # generate & sign command
    command = "t q {} {} {} {}".format(user_index, block_number, block_hash, userID)
    signedCommand = executeCommand(command).hex()

    return command, signedCommand


# generate UpdateBoundaryBlock commands
def makeUpdateBoundaryBlocks(addressNumber, updateNumber, maxBlockNumber):
    # generate temp block hashes
    block_hashes = []
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
    commands = pool.map(makeUpdateBoundaryBlocks_thread, params, 1)

    # write commands to files
    script_name = "scriptUpdate_{}_{}_{}".format(addressNumber, updateNumber, maxBlockNumber)
    signed_script_name = "signedUpdate_{}_{}_{}".format(addressNumber, updateNumber, maxBlockNumber)
    with open(SCRIPTS_PATH+script_name, "wt") as fscript, open(SCRIPTS_PATH+signed_script_name, "w") as fsigned:
        for cmd in commands:
            fscript.write(cmd[0]+"\n")
            fsigned.write(cmd[1]+"\n")
    print("  -> generated", script_name, "&", signed_script_name)


# split a file into several files
# ex. splitFile("signedPayment_50000_400000_1", 100000, "signedPayment_50000_100000_1-") -> creates 4 files
def splitFile(script, lineNumPerFile, splitedFileNamePrefix):
    cmd = [] 
    cmd.append("split -l ")
    cmd.append(str(lineNumPerFile))
    cmd.append(" -d ")
    cmd.append(script)
    cmd.append(" ")
    cmd.append(splitedFileNamePrefix)
    cmd = ''.join(cmd)

    # print("cmd:", cmd)
    os.system(cmd)


if __name__ == '__main__':
    # set multithreading pool
    THREAD_COUNT = multiprocessing.cpu_count()
    pool = Pool(THREAD_COUNT)
    # print("multithread count:", THREAD_COUNT)

    # if there is sys.argv input from command line, run a single script
    if len(sys.argv) >= 2:
        command = int(sys.argv[1])
    else:
        command = eval(input("which script do you want to make (0: all / 1: makeNewKeys / 2: makeNewAddresses / 3: makeAddUsers / 4: makeAddDeposits / 5: makePayments / 6: makeSettlements / 6: makeUpdateBoundaryBlocks): "))

    startTime = datetime.now()

    if command == 1:
        if len(sys.argv) >= 2:
            userNumber = int(sys.argv[2])
        else:
            userNumber = eval(input("how many keys to generate: "))
        makeNewKeys(userNumber)
    
    elif command == 2:
        if len(sys.argv) >= 2:
            addressNumber = int(sys.argv[2])
        else:
            addressNumber = eval(input("how many addresses to generate: "))
        makeNewAddresses(addressNumber)
    
    elif command == 3:
        if len(sys.argv) >= 2:
            accountNumber = int(sys.argv[2])
        else:
            accountNumber = eval(input("how many routee users to add: "))
        makeAddUsers(accountNumber)

    elif command == 4:
        if len(sys.argv) >= 2:
            userNumber = int(sys.argv[2])
            depositNumber = int(sys.argv[3])
        else:
            userNumber = eval(input("how many users in routee: "))
            depositNumber = eval(input("how many manager addresses to get: "))
        makeAddDeposits(userNumber, depositNumber)
        # dealWithDepositTxs(depositNumber) # this is for testing

    elif command == 5:
        if len(sys.argv) >= 2:
            userNumber = int(sys.argv[2])
            paymentNumber = int(sys.argv[3])
            batchSize = int(sys.argv[4])
        else:
            userNumber = eval(input("how many users in routee: "))
            paymentNumber = eval(input("how many rouTEE payments to execute: "))
            batchSize = eval(input("how many receivers per payment (batch size): "))
        makePayments(userNumber, paymentNumber, batchSize)

    elif command == 6:
        if len(sys.argv) >= 2:
            userNumber = int(sys.argv[2])
            settleNumber = int(sys.argv[3])
        else:
            userNumber = eval(input("how many users in routee: "))
            settleNumber = eval(input("how many rouTEE settlements to execute: "))
        makeSettlements(userNumber, settleNumber)

    elif command == 7:
        if len(sys.argv) >= 2:
            userNumber = int(sys.argv[2])
            updateNumber = int(sys.argv[3])
            maxBlockNumber = int(sys.argv[4])
        else:
            userNumber = eval(input("how many users in routee: "))
            updateNumber = eval(input("how many routee boundary block updates to execute: "))
            maxBlockNumber = eval(input("max block number in routee: "))
        makeUpdateBoundaryBlocks(userNumber, updateNumber, maxBlockNumber)

    elif command == 0:
        if len(sys.argv) >= 2:
            userNumber = int(sys.argv[2])
            depositNumber = int(sys.argv[3])
            paymentNumber = int(sys.argv[4])
            batchSize = int(sys.argv[5])
            settleNumber = int(sys.argv[6])
            updateNumber = int(sys.argv[7])
            maxBlockNumber = int(sys.argv[8])
        else:
            userNumber = eval(input("how many users in routee: "))
            depositNumber = eval(input("how many manager addresses to get: "))
            paymentNumber = eval(input("how many rouTEE payments to execute: "))
            batchSize = eval(input("  how many receivers per payment (batch size): "))
            settleNumber = eval(input("how many rouTEE settlements to execute: "))
            updateNumber = eval(input("how many routee boundary block updates to execute: "))
            maxBlockNumber = eval(input("  max block number in routee: "))

        if USE_SINGLE_KEY:
            makeNewKeys(1)
        else:
            makeNewKeys(userNumber)
        makeNewAddresses(userNumber)
        makeAddUsers(userNumber)
        makeAddDeposits(userNumber, depositNumber)
        makePayments(userNumber, paymentNumber, batchSize)
        makeSettlements(userNumber, settleNumber)
        makeUpdateBoundaryBlocks(userNumber, updateNumber, maxBlockNumber)

    else:
        print("wrong number, type other number to generate script")
        sys.exit()

    elapsed = datetime.now() - startTime
    print("elapsed time:", elapsed)
