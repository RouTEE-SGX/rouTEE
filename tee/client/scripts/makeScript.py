import random
import sys
# from bitcoinaddress import Wallet, Address, Key
import os.path
import csv
import ecdsa
import codecs
import hashlib

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

def makeNewAddresses(addressNumber):
    with open("scriptAddress", "wt") as f:
        for i in range(addressNumber):

            # wallet = Wallet()
            # print(wallet.address.privkey.hex)
            # print(wallet.address.pubkey)
            # print(wallet.address.pubaddr1_testnet)
            # with open("../key/private_key_user{}".format(i), "wb") as f1:
            #     f1.write(wallet.address.privkey.hex)

            # key = Key()
            # key.generate()

            # address = Address(key)
            # address._generate_publicaddress1_testnet()
            
            # f.write("{}\n".format(address.pubaddr1_testnet))

            sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
            vk = sk.get_verifying_key()
            with open("../key/private_key_user{}.pem".format(i), "wb") as f1:
                f1.write(sk.to_pem())
            with open("../key/public_key_user{}.pem".format(i), "wb") as f2:
                f2.write(vk.to_pem())

            public_key_bytes = b"\x04" +  vk.to_string()

            # Run SHA-256 for the public key
            sha256_bpk = hashlib.sha256(public_key_bytes)
            sha256_bpk_digest = sha256_bpk.digest()
            # Run RIPEMD-160 for the SHA-256
            ripemd160_bpk = hashlib.new('ripemd160')
            ripemd160_bpk.update(sha256_bpk_digest)
            ripemd160_bpk_digest = ripemd160_bpk.digest()

            ripemd160_bpk_hex = codecs.encode(ripemd160_bpk_digest, 'hex')

            network_bitcoin_public_key_bytes = b'\x6f' + ripemd160_bpk_digest

            sha256_nbpk = hashlib.sha256(network_bitcoin_public_key_bytes)
            sha256_nbpk_digest = sha256_nbpk.digest()
            sha256_2_nbpk = hashlib.sha256(sha256_nbpk_digest)
            sha256_2_nbpk_digest = sha256_2_nbpk.digest()
            sha256_2_hex = codecs.encode(sha256_2_nbpk_digest, 'hex')
            checksum = sha256_2_hex[:8]

            bitcoin_address = base58(codecs.encode(network_bitcoin_public_key_bytes, 'hex') + checksum)
            f.write("{}\n".format(bitcoin_address))
            # print("bitcoin_address: ", bitcoin_address)

def makeNewAccounts(accountNumber):
    if not os.path.exists("scriptAddress"):
        makeNewAddresses(accountNumber)
    addressFile = open("scriptAddress", 'r')
    rdr = csv.reader(addressFile)
    with open("scriptAddUser", "wt") as f:
        for address in rdr:
            settle_address = address[0]
        
            f.write("t v {} user{}\n".format(settle_address, rdr.line_num - 1))

def getReadyForDeposit(accountNumber):
    if not os.path.exists("scriptAddress"):
        makeNewAddresses(accountNumber)
    addressFile = open("scriptAddress", 'r')
    rdr = csv.reader(addressFile)
    with open("scriptDepositRequest", "wt") as f:
        for address in rdr:
            user_address = address[0]
        
            f.write("t j {} user{}\n".format(user_address, rdr.line_num - 1))

def dealWithDepositTxs(accountNumber):
    if not os.path.exists("scriptAddress"):
        print("execute makeNewAddresses first\n")
        return
    addressFile = open("scriptAddress", 'r')
    rdr = csv.reader(addressFile)
    with open("scriptDepositTx", "wt") as f:
        for address in rdr:
            user_address = address[0]
        
            f.write("r {} {} 100000000 100 user{}\n".format(user_address, rdr.line_num - 1, rdr.line_num - 1))

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

    with open("scriptPayment", "wt") as f:
        for i in range(paymentNumber):
            sender_index = random.randint(0, len(address_list) - 1)
            while True:
                receiver_index = random.randint(0, len(address_list) - 1)
                if sender_index != receiver_index:
                    break

            sender_address = address_list[sender_index]
            receiver_address = address_list[receiver_index]
        
            f.write("t m {} {} 10 1 user{}\n".format(sender_address, receiver_address, sender_index))

def settleBalanceRequest(settleTxNumber):
    if not os.path.exists("scriptAddress"):
        print("execute makeNewAddresses first\n")
        return

    addressFile = open("scriptAddress", 'r')
    rdr = csv.reader(addressFile)

    address_list = []
    for address in rdr:
        address_list.append(address[0])

    with open("scriptSettle", "wt") as f:
        for i in range(settleTxNumber):
            user_index = random.randint(0, len(address_list) - 1)

            user_address = address_list[user_index]
        
            f.write("t l {} 100000 user{}\n".format(user_address, user_index))

def updateLatestSPV(updateSPVNumber):
    if not os.path.exists("scriptAddress"):
        print("execute makeNewAddresses first\n")
        return

    addressFile = open("scriptAddress", 'r')
    rdr = csv.reader(addressFile)

    address_list = []
    for address in rdr:
        address_list.append(address[0])

    with open("scriptUpdateSPV", "wt") as f:
        for i in range(updateSPVNumber):
            user_index = random.randint(0, len(address_list) - 1)

            user_address = address_list[user_index]
        
            f.write("t q {} 3000 user{}\n".format(user_address, user_index))

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
        paymentNumber = eval(input("how many rouTEE payments to generate: "))
        doMultihopPayments(paymentNumber)
        settleRequestNumber = eval(input("how many rouTEE settle balance requests to generate: "))
        settleBalanceRequest(settleRequestNumber)
        updateSPVNumber = eval(input("how many rouTEE SPV block updates to generate: "))
        updateLatestSPV(updateSPVNumber)

        scriptName = "scriptForAll"

    print("make script [", scriptName, "] Done")