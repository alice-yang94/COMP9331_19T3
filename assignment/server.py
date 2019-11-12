#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# usage: python3 server.py server_port block_duration timeout
import sys      
from socket import *
from datetime import datetime
from collections import defaultdict
import threading
import time

def login(usern):
    clients[usern]['status'] = 'login'
    clients[usern]['login_time'] = datetime.now()
    clients[usern]['last_activate_time'] = datetime.now()
    # implement broadcast login here...

# returns logout_flag and response
def logout(usern, client, is_timeout):
    clients[usern]['status'] = 'logout'
    if is_timeout:
        status = 'TIMEOUT logout\n'
        msg = 'Timeout. You are logged out due to inactivity'
        return True, status + msg
    # user actively logout
    status = 'OK logout\n'
    return True, status

# check if usern is blocked
def check_blocked(usern):
    is_blocked = False
    if usern and clients[usern]['status'] == 'blocked':
        has_blocked_time = datetime.now() - clients[usern]['blocked_time']
        if has_blocked_time.seconds >= block_duration:
            # unblock
            clients[usern]['status'] = 'logout'
        else:
            # rsp: account is blocked
            is_blocked = True
    return is_blocked

# returns logout_flag and response
def authen_usern(input_usern, client):
    if input_usern in credentials.keys():
        # if usern is blocked
        if check_blocked(input_usern):
            status = 'ERROR login\n'
            msg = 'Your account is blocked due to multiple login failures. '\
                + 'Please try again later'
            return True, status + msg
        else:
            addr_to_user[client] = input_usern
            clients[input_usern]['status'] = 'authen'
            return False, 'authenticate Password\n'

    # response: line1 - responseStatus, line2 - message
    status = 'authenticate Username\n'
    msg = 'Invalid Username. Please try again'
    return False, status + msg

# returns logout_flag and response
def authen_passw(passw, usern, client):
    if credentials[usern] == passw:
        login(usern)
        status = 'OK login\n'
        msg = 'Welcome to the greatest messaging application ever!'
        return False, status + msg
    
    if 'count' in clients[usern].keys():
        clients[usern]['count'] += 1
        if clients[usern]['count'] == 3:
            clients[usern]['status'] = 'blocked'
            clients[usern]['blocked_time'] = datetime.now()
            
            status = 'ERROR login\n'
            msg = 'Invalid Password. Your account has been blocked. ' \
                + 'Please try again later'
            return True, status + msg
    else:
        clients[usern]['count'] = 1

    status = 'authenticate Password\n'
    msg = 'Invalid Password. Please try again'
    return False, status + msg

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

# returns logout_flag and response
def get_response(request, usern, client):
    tokens = request.split()
    if len(tokens) == 1:
        if tokens[0] == 'whoelse':
            return False, display_online_users()
        elif tokens[0] == 'logout':
            return logout(usern, client, False)

    elif len(tokens) == 2:
        if tokens[0] == 'broadcast':
            return False, broadcast()
        elif tokens[0] == 'whoelsesince':
            return False, whoelsesince()
        elif tokens[0] == 'block':
            return False, block()
        elif tokens[0] == 'unblock':
            return False, unblock()

    elif len(tokens) == 3:
        if tokens[0] == 'message':
            return False, send_msg(tokens)
        elif tokens[0] == 'authenticate':
            if tokens[1] == 'Username':
                return authen_usern(tokens[2], client)
            elif tokens[1] == 'Password':
                return authen_passw(tokens[2], usern, client)

    return False, 'Error. Invalid command\n'

# connection handler, handle new clients connect to the server
def conn_handler():
    while True:
        try:
            # Establish connection with client.
            client_socket, client_addr = server_socket.accept()
            # set client socket to non blocking
            client_socket.setblocking(False)
            # For debug: 
            print('Got connection from', client_addr)
            with t_lock:         
                response = ''
                # new connection setup
                addr_to_user[(client_socket, client_addr)] = ''
                # ask for username
                response = 'authenticate Username\n'

                # Send the responseStatus and message back to the client
                client_socket.send(response.encode())

                # notify the thread waiting
                t_lock.notify()
        except:
            pass

def request_handler(client, usern, client_socket):
    logout_flag = False
    try:
        # Get the request data
        request = client_socket.recv(2048).decode()
        if usern and clients[usern]['status'] == 'login':
            clients[usern]['last_activate_time'] = datetime.now()
        logout_flag, response = get_response(request, usern, client)
        if response:
            # Send the responseStatus and message back to the client
            client_socket.send(response.encode())
        if logout_flag:
            # for debug
            print('closing connection: ', client)
            client_socket.close()
    except:
        # if no request catched, continue
        pass
    return logout_flag

def recv_handler():
    while True:
        with t_lock:
            clients_logout = [] 
            for client in addr_to_user:
                client_socket, _ = client
                usern = addr_to_user[client]
                logout_flag = request_handler(client, usern, client_socket)
                if logout_flag:
                    clients_logout.append(client)
            for client in clients_logout:
                addr_to_user.pop(client, None)
            t_lock.notify()

def send_handler():
    while True:
        with t_lock:
            for client in addr_to_user:
                usern = addr_to_user[client]
                client_socket, _ = client
                # if the client has username and its status is login
                if usern and clients[usern]['status'] == 'login' and \
                    ((datetime.now() - clients[usern]['last_activate_time']).seconds) >= timeout:
                    _, msg = logout(usern, client, True)
                    client_socket.send(msg.encode())
                    # for debug
                    print('closing connection: ', client)
                    client_socket.close()
            t_lock.notify()
        # sleep for 1s
        time.sleep(UPDATE_INTERVAL)

def main():
    global clients, addr_to_user, t_lock
    # Store clients info in clients = {username: user_info_dict}
    user_info_keys = ['client_addr', 'login_time', 'status', 
                      'last_activate_time', 'blocked_time']
    clients = defaultdict(lambda: dict.fromkeys(user_info_keys))
    # addr_to_user = {(client_socket, client_addr): username}
    addr_to_user = {}
    
    # Create a TCP socket object(streaming)
    global server_socket
    server_socket = socket(AF_INET, SOCK_STREAM)
    # read server_port, block_duration and timeout from command line
    server_port = int(sys.argv[1])
    # Bind localhost and port with our socket
    server_socket.bind(('localhost', server_port)) 

    global block_duration, timeout, credentials
    block_duration = int(sys.argv[2])
    timeout = int(sys.argv[3])
    # load credentials into a dictionary
    credentials = {}
    with open('credentials.txt','r') as cred_file:
        for line in cred_file:
            username, password = line.split()
            credentials[username] = password

    global t_lock, UPDATE_INTERVAL
    # threading lock for multiple threads to access shared datastructure
    t_lock = threading.Condition()
    # would communicate with clients after every second
    UPDATE_INTERVAL = 1

    # Wait for client connection, queue up to 10 connect request
    server_socket.listen(10)

    conn_thread=threading.Thread(name = "ConnHandler",target = conn_handler)
    conn_thread.daemon=True
    conn_thread.start()
    
    recv_thread = threading.Thread(name = "RecvHandler", target = recv_handler)
    recv_thread.daemon = True
    recv_thread.start()

    send_thread=threading.Thread(name = "SendHandler",target = send_handler)
    send_thread.daemon=True
    send_thread.start()

    while True:
        time.sleep(0.1)
           
if __name__ == "__main__":
    main()
