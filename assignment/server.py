#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# usage: python3 server.py server_port block_duration timeout
import sys      
import socket
from datetime import datetime
from collections import defaultdict


def login(usern):
    clients[usern]['status'] = 'login'
    clients[usern]['login_time'] = datetime.now()
    clients[usern]['last_activate_time'] = datetime.now()
    # implement broadcast login here...

def logout(usern, client_addr, is_timeout):
    clients[usern]['status'] = 'logout'
    addr_to_user[client_addr] = None
    if is_timeout:
        status = 'TIMEOUT logout\n'
        msg = 'Timeout. You are logged out due to inactivity'
        return status + msg
    # user actively logout
    status = 'OK logout\n'
    return status

def authen_usern(input_usern, client_addr):
    if input_usern in credentials.keys():
        addr_to_user[client_addr] = input_usern
        clients[input_usern]['status'] = 'authen'
        return 'authenticate Password\n'

    # response: line1 - responseStatus, line2 - message
    status = 'authenticate Username\n'
    msg = 'Invalid Username. Please try again'
    return status + msg

def authen_passw(passw, usern):
    if credentials[usern] == passw:
        login(usern)
        status = 'OK login\n'
        msg = 'Welcome to the greatest messaging application ever!'
        return status + msg
    
    if 'count' in clients[usern].keys():
        clients[usern]['count'] += 1
        if clients[usern]['count'] == 3:
            status = 'ERROR login\n'
            msg = 'Invalid Password. Your account has been blocked. ' \
                + 'Please try again later'
            return status + msg
    else:
        clients[usern]['count'] = 1

    status = 'authenticate Password\n'
    msg = 'Invalid Password. Please try again'
    return status + msg

def display_online_users():
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

def get_response(request, usern, client_addr):
    tokens = request.split()
    if len(tokens) == 1:
        if tokens[0] == 'whoelse':
            return display_online_users()
        elif tokens[0] == 'logout':
            return logout(usern, client_addr, False)

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
                return authen_passw(tokens[2], usern)

    return 'Error. Invalid command\n'

def request_handler(client_socket, client_addr):
    response = ''
    logout_flag = False
    if client_addr not in addr_to_user.keys():
        # new connection setup
        addr_to_user[client_addr] = ''
        # ask for username
        response += 'authenticate Username\n'
    
    else:
        usern = addr_to_user[client_addr]

        # if the client has username and its status is login
        if usern and clients[usern]['status'] == 'login' and \
            ((datetime.now() - clients[usern]['last_activate_time']).seconds) >= timeout:

            # For debug:
            #print('last_activate_time: ', clients[usern]['last_activate_time'])
            #print('now: ', datetime.now())
            #print('timeout: {}, diff: {}'.format(timeout, (datetime.now() - clients[usern]['last_activate_time']).seconds))

            logout_flag = True
            response += logout(usern, client_addr, True)
        else:
            try:
                # Get the request data
                request = client_socket.recv(2048).decode()
                if request:     
                    #For debug:
                    print('request: ', request)
                    
                    if request == 'logout':
                        logout_flag = True
                        response += logout(usern, client_addr, False)
                    else:
                        if usern and clients[usern]['status'] == 'login':
                            clients[usern]['last_activate_time'] = datetime.now()
                        response += get_response(request, usern, client_addr)
            except:
                # if no request catched, continue
                pass

    if response:
        # For debug:
        #print('sending: ', response)

        # Send the responseStatus and message back to the client
        client_socket.send(response.encode())

    return logout_flag

def main():
    global clients, addr_to_user, online_users
    # Store clients info in this dictionary
    # clients = {username: user_info_dict}
    user_info_keys = ['client_addr', 'login_time', 'status', 
                      'last_activate_time', 'block_time']
    clients = defaultdict(lambda: dict.fromkeys(user_info_keys))
    # addr_to_user = {client_addr: username}
    addr_to_user = {}
    # online_users = [username]
    online_users = []
    
    # Create a TCP socket object(streaming)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)        
    
    # read server_port, block_duration and timeout from command line
    server_port = int(sys.argv[1])
    s.bind(('localhost', server_port)) # Bind localhost and port with our socket

    global block_duration, timeout, credentials
    block_duration = int(sys.argv[2])
    timeout = int(sys.argv[3])

    # load credentials into a dictionary
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
        
        client_socket.setblocking(False)
        # For debug: 
        print('Got connection from', client_addr)

        logout_flag = False
        while not logout_flag:
            # return False if logout (either from user msg or timeout)
            logout_flag = request_handler(client_socket, client_addr)

        # Close the connection
        client_socket.close()                
           
if __name__ == "__main__":
    main()
