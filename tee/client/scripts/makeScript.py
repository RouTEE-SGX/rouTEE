import random

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
    command = eval(input("which script do you want to make (1: createChannels / 2: doRandomPayments): "))
    
    if command == 1:
        channelNumber = eval(input("how many channels: "))
        scriptName = input("script name: ")
        createChannels(channelNumber, scriptName)

    elif command == 2:
        paymentNumber = eval(input("how many payments: "))
        maxUserNumber = eval(input("what is max user index number: "))
        scriptName = input("script name: ")
        doRandomPayments(paymentNumber, maxUserNumber, scriptName)

    else:
        print("wrong command")
