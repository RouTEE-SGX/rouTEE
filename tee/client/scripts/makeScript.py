import random
import sys
from bitcoinaddress import Wallet, Address, Key
import os.path
import csv
import ecdsa
import codecs
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC, RSA
from Crypto.Signature import DSS, pkcs1_15

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

    # # encryption using ECDSA
    # try:
    #     with open("../key/private_key_{}.pem".format(user), "rb") as f:
    #         sk = ecdsa.SigningKey.from_pem(f.read())
    #     with open("../key/public_key_{}.pem".format(user), "rb") as f:
    #         vk = ecdsa.VerifyingKey.from_pem(f.read())
    # except:
    #     print("no user key")
    #     print("public_key_{}.pem".format(user))
    #     exit()

    # encryption using RSA
    try:
        with open("../key/private_key_{}.pem".format(user), "rb") as f:
            sk = RSA.import_key(f.read())
        with open("../key/public_key_{}.pem".format(user), "rb") as f:
            vk = RSA.import_key(f.read())
    except:
        print("no user key")
        exit()

    # if isForDeposit:
    #     pubkey = b"\x04" + vk.pubkey.point.x().to_bytes(32, 'big') + vk.pubkey.point.y().to_bytes(32, 'big')
    #     command = command + b" " + pubkey

    # sig = sk.sign(command, hashfunc=hashlib.sha256)
    # # print(command)

    # try:
    #     vk.verify(sig, command, hashfunc=hashlib.sha256)
    # except:
    #     print("bad signature")
    #     exit()

    if isForDeposit:
        pubkey = (vk.n).to_bytes(384, 'little')
        pubkey_hex = pubkey.hex()
        # print(pubkey_hex)
        message = command + b" " + pubkey
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
        # print("secure command")
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

# Generate ECC private key, public key and bitcoin address
def makeNewAddresses(addressNumber):
    with open("scriptAddress", "wt") as f:
        for i in range(addressNumber):

            userID = "user" + format(i, '03')

            private_key = RSA.generate(3072)
            public_key = private_key.publickey()

            with open("../key/private_key_{}.pem".format(userID), "wb") as f1:
                f1.write(private_key.export_key('PEM'))
            with open("../key/public_key_{}.pem".format(userID), "wb") as f2:
                f2.write(public_key.export_key('PEM'))

            key = Key()
            key.generate()

            address = Address(key)
            address._generate_publicaddress1_testnet()
            
            f.write("{}\n".format(address.pubaddr1_testnet))


            # sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
            # vk = sk.get_verifying_key()
            # with open("../key/private_key_{}.pem".format(userID), "wb") as f1:
            #     f1.write(sk.to_pem())
            # with open("../key/public_key_{}.pem".format(userID), "wb") as f2:
            #     f2.write(vk.to_pem())

            # public_key_bytes = b"\x04" +  vk.to_string()

            # # Run SHA-256 for the public key
            # sha256_bpk = hashlib.sha256(public_key_bytes)
            # sha256_bpk_digest = sha256_bpk.digest()
            # # Run RIPEMD-160 for the SHA-256
            # ripemd160_bpk = hashlib.new('ripemd160')
            # ripemd160_bpk.update(sha256_bpk_digest)
            # ripemd160_bpk_digest = ripemd160_bpk.digest()

            # ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')

            # network_bitcoin_public_key_bytes = b'\x6f' + ripemd160_bpk_digest

            # # Double hashing for checksum
            # sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
            # sha256_nbpk_digest = sha256_nbpk.digest()
            # sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
            # sha256_2_nbpk_digest = sha256_2_nbpk.digest()
            # sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
            # checksum = sha256_2_hex[:8]

            # # base58 encoding
            # bitcoin_address = base58(codecs.encode(network_bitcoin_public_key_bytes, 'hex') + checksum)
            # f.write("{}\n".format(bitcoin_address))
            # # print("bitcoin_address: ", bitcoin_address)

# Script for generating rouTEE accounts
def makeNewAccounts(accountNumber):
    if not os.path.exists("scriptAddress"):
        makeNewAddresses(accountNumber)
    addressFile = open("scriptAddress", 'r')
    rdr = csv.reader(addressFile)
    with open("scriptAddUser", "wt") as fscript, open("signedAddUser", "w") as fsigned:
        for address in rdr:
            sender_address = address[0]
            settle_address = sender_address
            userID = "user" + format(rdr.line_num - 1, '03')
            command = "t v {} {} {}".format(sender_address, settle_address, userID)
            fscript.write(command + "\n")

            signedCommand = executeCommand(command)
            fsigned.write(signedCommand.hex())
            fsigned.write('\n')

# Script for generating deposit requests
def getReadyForDeposit(accountNumber):
    if not os.path.exists("scriptAddress"):
        makeNewAddresses(accountNumber)
    addressFile = open("scriptAddress", 'r')
    rdr = csv.reader(addressFile)
    with open("scriptDepositReq", "wt") as fscript, open("signedDepositReq", "w") as fsigned:
        for address in rdr:
            user_address = address[0]
            userID = "user" + format(rdr.line_num - 1, '03')        
            command = "t j {} {}".format(user_address, userID)
            fscript.write(command + "\n")

            signedCommand = executeCommand(command)
            fsigned.write(signedCommand.hex())
            fsigned.write('\n')

# Script for managing deposit transactions
# Should be used only for testing
def dealWithDepositTxs(accountNumber):
    if not os.path.exists("scriptAddress"):
        print("execute makeNewAddresses first\n")
        return
    addressFile = open("scriptAddress", 'r')
    rdr = csv.reader(addressFile)
    with open("scriptDepositTx", "wt") as fscript, open("signedDepositTx", "w") as fsigned:
        for address in rdr:
            user_address = address[0]
            userID = "user" + format(rdr.line_num - 1, '03')         
            command = "r {} 0 100000000 100 {}".format(user_address, userID)
            fscript.write(command + "\n")

            signedCommand = executeCommand(command)
            fsigned.write(signedCommand.hex())
            fsigned.write('\n')

# Script for payments among users
def doMultihopPayments(paymentNumber):
    if not os.path.exists("scriptAddress"):
        print("execute makeNewAddresses first\n")
        return

    addressFile = open("scriptAddress", 'r')
    rdr = csv.reader(addressFile)
    #accountNum = sum(1 for row in rdr)

    address_list = []
    for address in rdr:
        address_list.append(address[0])

    with open("scriptPayment", "wt") as fscript, open("signedPayment", "w") as fsigned:
        for i in range(paymentNumber):
            sender_index = random.randint(0, len(address_list) - 1)
            while True:
                receiver_index = random.randint(0, len(address_list) - 1)
                if sender_index != receiver_index:
                    break

            sender_address = address_list[sender_index]
            receiver_address = address_list[receiver_index]
            senderID = "user" + format(sender_index, '03')        
            command = "t m {} {} 10 1 {}".format(sender_address, receiver_address, senderID)
            fscript.write(command + "\n")

            signedCommand = executeCommand(command)
            fsigned.write(signedCommand.hex())
            fsigned.write('\n')

# Script for generating settle requests
def settleBalanceRequest(settleTxNumber):
    if not os.path.exists("scriptAddress"):
        print("execute makeNewAddresses first\n")
        return

    addressFile = open("scriptAddress", 'r')
    rdr = csv.reader(addressFile)

    address_list = []
    for address in rdr:
        address_list.append(address[0])

    with open("scriptSettleReq", "wt") as fscript, open("signedSettleReq", "w") as fsigned:
        for i in range(settleTxNumber):
            user_index = random.randint(0, len(address_list) - 1)

            user_address = address_list[user_index]
            userID = "user" + format(user_index, '03')
            command = "t l {} 100000 {}".format(user_address, userID)
            fscript.write(command + "\n")

            signedCommand = executeCommand(command)
            fsigned.write(signedCommand.hex())
            fsigned.write('\n')

# Script for updating boundary block number
def updateLatestSPV(updateSPVNumber):
    if not os.path.exists("scriptAddress"):
        print("execute makeNewAddresses first\n")
        return

    addressFile = open("scriptAddress", 'r')
    rdr = csv.reader(addressFile)

    address_list = []
    for address in rdr:
        address_list.append(address[0])

    with open("scriptUpdateSPV", "wt") as fscript, open("signedUpdateSPV", "w") as fsigned:
        for i in range(updateSPVNumber):
            user_index = random.randint(0, len(address_list) - 1)

            user_address = address_list[user_index]
            userID = "user" + format(user_index, '03')
            command = "t q {} 3000 {}".format(user_address, userID)
            fscript.write(command + "\n")

            signedCommand = executeCommand(command)
            fsigned.write(signedCommand.hex())
            fsigned.write('\n')

def createChannels(channelNumber, scriptName):

    with open(scriptName, "w+") as f:
        for i in range(channelNumber):
            f.write("j user " + str(i+1) + "\n")

def doRandomPayments(paymentNumber, maxUserNumber, scriptName):
    
    with open(scriptName, "w+") as f:
        for i in range(paymentNumber):
            # select distinct random sender / receiver
            randomSenderAddr = random.randint(1, maxUserNumber)
            randomReceiverAddr = randomSenderAddr
            while (randomReceiverAddr == randomSenderAddr):
                randomReceiverAddr = random.randint(1, maxUserNumber)

            # cmd: sender receiver sendAmount routingFee
            f.write("m user_" + str(randomSenderAddr) + " user_" + str(randomReceiverAddr) + " " + str(1) + " " + str(2) + "\n")



if __name__ == '__main__':

    # if there is sys.argv input from command line, run a single script
    if len(sys.argv) >= 2:
        command = int(sys.argv[1])
    else:
        command = eval(input("which script do you want to make (0: default / 1: createChannels / 2: doRandomPayments / 3: makeNewAddresses / 4: makeNewAccounts / 5: doMultihopPayments / 6: settleBalanceRequest / 7: updateLatestSPV)): "))
    
    if command == 1:
        if len(sys.argv) >= 2:
            channelNumber = int(sys.argv[2])
            scriptName = sys.argv[3]
        else:
            channelNumber = eval(input("how many channels: "))
            scriptName = input("script name: ")
        createChannels(channelNumber, scriptName)

    elif command == 2:
        if len(sys.argv) >= 2:
            paymentNumber = int(sys.argv[2])
            maxUserNumber = int(sys.argv[3])
            scriptName = sys.argv[4]
        else:
            paymentNumber = eval(input("how many payments: "))
            maxUserNumber = eval(input("what is max user index number: "))
            scriptName = input("script name: ")
        doRandomPayments(paymentNumber, maxUserNumber, scriptName)

    elif command == 3:
        if len(sys.argv) >= 2:
            addressNumber = int(sys.argv[2])
            scriptName = sys.argv[3]
        else:
            addressNumber = eval(input("how many bitcoin addresses to generate: "))
            scriptName = "scriptAddress"
        makeNewAddresses(addressNumber)

    elif command == 4:
        if len(sys.argv) >= 2:
            accountNumber = int(sys.argv[2])
            scriptName = sys.argv[3]
        else:
            accountNumber = eval(input("how many routee accounts to generate: "))
            scriptName = "scriptAccount"
        makeNewAccounts(accountNumber)

    elif command == 5:
        if len(sys.argv) >= 2:
            paymentNumber = int(sys.argv[2])
            scriptName = sys.argv[3]
        else:
            paymentNumber = eval(input("how many rouTEE payments to generate: "))
            scriptName = "scriptPayment"
        doMultihopPayments(paymentNumber)

    elif command == 6:
        if len(sys.argv) >= 2:
            settleRequestNumber = int(sys.argv[2])
            scriptName = sys.argv[3]
        else:
            settleRequestNumber = eval(input("how many rouTEE settle balance requests to generate: "))
            scriptName = "scriptSettle"
        settleBalanceRequest(settleRequestNumber)

    elif command == 7:
        if len(sys.argv) >= 2:
            updateSPVNumber = int(sys.argv[2])
            scriptName = sys.argv[3]
        else:
            updateSPVNumber = eval(input("how many rouTEE SPV block update: "))
            scriptName = "scriptUpdateSPV"
        updateLatestSPV(updateSPVNumber)

    elif command == 0:
        accountNumber = eval(input("how many routee accounts to generate: "))
        makeNewAddresses(accountNumber)
        makeNewAccounts(accountNumber)
        getReadyForDeposit(accountNumber)
        dealWithDepositTxs(accountNumber)
        settleBalanceRequest(accountNumber)
        updateLatestSPV(accountNumber)
        paymentNumber = eval(input("how many rouTEE payments to generate: "))
        doMultihopPayments(paymentNumber)
        # settleRequestNumber = eval(input("how many rouTEE settle balance requests to generate: "))
        # settleBalanceRequest(settleRequestNumber)
        # updateSPVNumber = eval(input("how many rouTEE SPV block updates to generate: "))
        # updateLatestSPV(updateSPVNumber)

        scriptName = "scriptForAll"

    print("make script [", scriptName, "] Done")
