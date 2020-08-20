# if need to install python3
# https://somjang.tistory.com/entry/PythonUbuntu%EC%97%90-Python-37-%EC%84%A4%EC%B9%98%ED%95%98%EA%B8%B0

import socket
from datetime import datetime
import csv
import sys

# rouTEE IP
HOST = "127.0.0.1"
PORT = 7223

# command scripts for rouTEE
SCRIPTSPATH = "scripts/"

# open socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# connect to the server
client_socket.connect((HOST, PORT))

# get file length
def file_len(fileName):
    with open(fileName) as f:
        for i, l in enumerate(f):
            pass
    return i + 1

# execute the script for rouTEE
def runScript(fileName):
    print("run script", fileName, "\n")

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

        # send command to server
        startTime = datetime.now()
        client_socket.sendall(command[0].encode())

        # get response from server
        data = client_socket.recv(1024)
        elapsed = datetime.now() - startTime

        # check the result
        if data.decode() != "SUCCESS":
            print("ERROR: command failed\n")
            print("error msg:", data.decode())
            return

        # calculate elapsed time
        elapsedMicrosec = elapsed.seconds * 1000000 + elapsed.microseconds
        elapsedMillisec = elapsedMicrosec / 1000.0
        elapsedSec = elapsedMillisec / 1000.0
        elapsedTimeSum = elapsedTimeSum + elapsedMicrosec

        # print results
        if cnt%printEpoch == 0:
            print("script cmd (", cnt, "/", cmdNumber, ") :", command[0])
            print("elapsed time:", elapsed)
            print('Received:', data.decode())
            print("elapsed:", elapsedMicrosec, "microsec /", elapsedMillisec, "millisec /", elapsedSec, "sec\n")

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
    print("run script elapsed time:", totalElapsed, "\n")
    print("elapsed time sum:", elapsedTimeSum, "ms")

    try:
        print("payment count:", paymentCount, "/ payment execution time:", paymentTimeSum, "( avg time:", paymentTimeSum/paymentCount, "ms )")
    except:
        print("payment count:", 0, "/ payment execution time:", 0, "( avg time:", 0, "ms )")
    try:
        print("settle count:", settleCount, "/ settle execution time:", settleTimeSum, "( avg time:", settleCount/settleTimeSum, "ms )")
    except:
        print("settle count:", 0, "/ settle execution time:", 0, "( avg time:", 0, "ms )")
    try:
        print("create channel count:", createChannelCount, "/ create channel execution time:", createChannelTimeSum, "( avg time:", createChannelTimeSum/createChannelCount, "ms )")
    except:
        print("create channel count:", 0, "/ create channel execution time:", 0, "( avg time:", 0, "ms )")

    print("")
    return



if __name__ == "__main__":

    # if there is sys.argv input from command line, run a single script
    if len(sys.argv) == 2:
        scriptName = sys.argv[1]
        runScript(scriptName)
        sys.exit()

    while (True):
        command = input("input command: ")
        if len(command) == 0:
            # ignore '\n'
            print("")
            continue
        
        if command[0] == 's':
            # execute script
            runScript(command)
            continue
        
        # send command to server
        startTime = datetime.now()
        client_socket.sendall(command.encode())

        # get response from server
        data = client_socket.recv(1024)
        elapsed = datetime.now() - startTime
        print(elapsed)
        print('Received:', data.decode())

        # print elapsed time
        elapsedMicrosec = elapsed.seconds * 1000000 + elapsed.microseconds
        elapsedMillisec = elapsedMicrosec / 1000.0
        elapsedSec = elapsedMillisec / 1000.0
        print("elapsed:", elapsedMicrosec, "microsec /", elapsedMillisec, "millisec /", elapsedSec, "sec\n")
    
    # close socket
    client_socket.close()
