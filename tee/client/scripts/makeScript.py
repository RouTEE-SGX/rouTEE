import random
import sys

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

def doRandomVotings(votingNumber, maxPolicyNumber, scriptName):

    with open(scriptName, "w+") as f:
        for i in range(votingNumber):
            # select random policy to vote
            randomPolicyIndex = random.randint(0, maxPolicyNumber-1)

            # cmd: policyIndex ballotNum (hardcoded: 100)
            f.write("q e " + str(randomPolicyIndex) + " 100\n")

if __name__ == '__main__':

    # if there is sys.argv input from command line, run a single script
    if len(sys.argv) >= 2:
        command = int(sys.argv[1])
    else:
        command = eval(input("which script do you want to make (1: createChannels / 2: doRandomPayments / 3: doRandomVotings): "))
    
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
        votingNumber = eval(input("how many votings: "))
        maxPolicyNumber = eval(input("how many policies: "))
        scriptName = input("script name: ")
        doRandomVotings(votingNumber, maxPolicyNumber, scriptName)

    print("make script [", scriptName, "] Done")
