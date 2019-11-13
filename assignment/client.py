#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#Usage: python3 client.py server_addr server_port
import socket
import select
import sys

# handle the data received from server
def data_handler(data):
    global curr_state
    status, msg = data.split('\n',1)
    status = status.split()
    if msg:
        print(msg)

    if status[0] == 'authenticate':
        response = input(status[1] + ': ')
        # format: authenticate Username/Password xxx
        return ' '.join([status[0], status[1], response])

    # change current state of client of login/logout
    if status[0] == 'OK' \
        and (status[1] == 'login' or status[1] == 'logout'):
        curr_state = status[1]

    # logout if received timeout msg from server due to inactivity
    # or account blocked due to multiple attempts of wrong passwords
    elif status[0] == 'TIMEOUT' \
        or (status[0] == 'ERROR' and status[1] == 'login'):
        curr_state = 'logout'

    # all other status is used for debugging, no respond needed
    return ''

def main():
    # Read server name and port number from command line
    serverName = sys.argv[1]
    serverPort = int(sys.argv[2])
    server_address = (serverName, serverPort)

    # create tcp socket
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # connect to server
    clientSocket.connect(server_address)
    # set clientSocket to non-blocking
    clientSocket.setblocking(False)
    
    # curr_state: authen/login/logout
    global curr_state
    curr_state = 'authen'
    
    while curr_state != 'logout':
        # since clientSocket is non-blocking, use try to recv data, if 
        #nothing received, continue
        try:
            data = clientSocket.recv(2048).decode()
            if data:
                response = data_handler(data).encode()
                if curr_state != 'logout' and response:
                    clientSocket.sendto(response, server_address)
        except:
            pass

        # if login and there is input, send it to server, else continue
        if curr_state == 'login' \
            and sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
            request = sys.stdin.readline()
            if request:
                # remove newline by [:-1]
                request = request[:-1].encode()
                clientSocket.sendto(request, server_address)
            else:
                print('Error. Empty command')

    # Close the socket
    clientSocket.close()
    
           
if __name__ == "__main__":
    main()
