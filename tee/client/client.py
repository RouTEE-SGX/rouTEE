# if need to install python3
# https://somjang.tistory.com/entry/PythonUbuntu%EC%97%90-Python-37-%EC%84%A4%EC%B9%98%ED%95%98%EA%B8%B0

import socket
from datetime import datetime

HOST = "127.0.0.1"
PORT = 7223

# open socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# connect to the server
client_socket.connect((HOST, PORT))

# send cmd to server
command = "k"
startTime = datetime.now()
client_socket.sendall(command.encode())

# get response from server
data = client_socket.recv(1024)
input()
elapsed = datetime.now() - startTime
print elapsed
print 'Received:', data

elapsedMicrosec = elapsed.seconds*1000000 + elapsed.microseconds
elapsedMillisec = elapsedMicrosec/1000.0
elapsedSec = elapsedMillisec/1000.0
print "elapsed:", elapsedMicrosec, "microsec /", elapsedMillisec, "millisec /", elapsedSec, "sec"

# close socket
client_socket.close()
