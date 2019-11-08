#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# usage: python3 server.py server_port block_duration timeout
import sys      
import socket
from datetime import datetime

def login(client_addr):
    clients[client_addr]['status'] = 'login'
    clients[client_addr]['login_time'] = datetime.now()
    # implement broadcast login here...

def authen_usern(usern, client_addr):
    if usern in credentials.keys():
        clients[client_addr]['username'] = usern
        return 'authenticate Password\n'
    # rsp: response to the authenticate request
    # line1 - status, line2 - message
    rsp = 'authenticate Username\n'
    rsp += 'Invalid Username. Please try again'
    return rsp

def authen_passw(passw, client_addr):
    usern = clients[client_addr]['username']
    # rsp: response to the authenticate request
    # line1 - status, line2 - message
    if credentials[usern] == passw:
        login(client_addr)
        rsp = 'OK login\n'
        rsp += 'Welcome to the greatest messaging application ever!'
        return rsp
    
    if 'count' in clients[client_addr].keys():
        clients[client_addr]['count'] += 1
        if clients[client_addr]['count'] == 3:
            rsp = 'ERROR login\n'
            rsp += 'Invalid Password. Your account has been blocked. ' \
                 + 'Please try again later'
            return rsp
    else:
        clients[client_addr]['count'] = 1

    rsp = 'authenticate Password\n'
    rsp += 'Invalid Password. Please try again'
    return rsp


def display_online_users():
    return ''

def logout():
    return ''

def broadcast():
    return ''

def whoelsesince():
    return ''

def block():
    return ''

def unblock():
    return ''

def send_msg(tokens):
    #user = str(tokens[1])
    #message = str(tokens[2])
    return ''


def request_handler(request, client_addr):
    tokens = request.split()
    if len(tokens) == 1:
        if tokens[0] == 'whoelse':
            return display_online_users()
        elif tokens[0] == 'logout':
            return logout()

    elif len(tokens) == 2:
        if tokens[0] == 'broadcast':
            return broadcast()
        elif tokens[0] == 'whoelsesince':
            return whoelsesince()
        elif tokens[0] == 'block':
            return block()
        elif tokens[0] == 'unblock':
            return unblock()

    elif len(tokens) == 3:
        if tokens[0] == 'message':
            return send_msg(tokens)
        elif tokens[0] == 'authenticate':
            if tokens[1] == 'Username':
                return authen_usern(tokens[2], client_addr)
            elif tokens[1] == 'Password':
                return authen_passw(tokens[2], client_addr)

    return 'Error. Invalid command\n'


def main():
    # Store clients info in this list
    # clients = {(client_addr, client_port): dict}
    # dict = {'usern':_, login_time':_, 'status':_, 'timeout_remain':_,...}
    global clients
    clients = {}
    
    # Create a TCP socket object(streaming)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        
    
    # read server_port, block_duration and timeout from command line
    server_port = int(sys.argv[1])
    server_addr = 'localhost'
    s.bind((server_addr, server_port)) # Bind localhost and port with our socket

    #block_duration = int(sys.argv[2])
    #timeout = int(sys.argv[3])

    # load credentials into a dictionary
    global credentials
    credentials = {}
    with open('credentials.txt','r') as cred_file:
        for line in cred_file:
            username, password = line.split()
            credentials[username] = password
    
    # Wait for client connection, queue up to 1 connect request
    s.listen(1)  
    
    while True:
        # Establish connection with client.
        client_socket, client_addr = s.accept()    

        # For debug: 
        print('Got connection from', client_addr)

        while True:
            response = ''
            if client_addr not in clients.keys():
                # new connection setup
                clients[client_addr] = {}
                # ask for username
                response += 'authenticate Username\n'
            else:
                # Get the request data
                request = client_socket.recv(4096).decode()
                response += request_handler(request, client_addr)

                # For debug: 
                print('request: ', request)

            print('sending...')
        
            # Send the status and message back to the client
            client_socket.send(response.encode())

        # Close the connection
        client_socket.close()                

           
           
if __name__ == "__main__":
    main()
