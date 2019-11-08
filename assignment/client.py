#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#Usage: python3 client.py server_addr server_port
import socket
import sys

def data_handler(data):
    status, msg = data.split('\n',1)
    status = status.split()
    if msg:
        print(msg)

    if status[0] == 'authenticate':
        response = input(status[1] + ': ')
        # format: authenticate Username/Password xxx
        return ' '.join([status[0], status[1], response])

    if status[0] == 'OK':
        if status[1] == 'login':
            return ''
        else:
            # implement other status types
            return ''    
    
    # status[0] == 'ERROR'
    if status[1] == 'login':
        return ''
    else:
        # implement other status types
        return ''


# Read server name and port number from command line
serverName = sys.argv[1]
serverPort = int(sys.argv[2])
server_address = (serverName, serverPort)

# create tcp socket
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# connect to server
clientSocket.connect(server_address)
logout = False
while not logout:
    data = clientSocket.recv(4096).decode()
    if data:
        response = data_handler(data).encode()
        clientSocket.sendto(response, server_address)

clientSocket.close()
# Close the socket
