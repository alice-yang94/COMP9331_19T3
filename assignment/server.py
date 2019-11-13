#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# usage: python3 server.py server_port block_duration timeout
import sys      
from socket import *
from datetime import datetime
from collections import defaultdict
import threading
import time

def login(usern, client):
    clients[usern]['status'] = 'login'
    clients[usern]['login_time'] = datetime.now()
    clients[usern]['last_activate_time'] = datetime.now()
    clients[usern]['socket_and_addr'] = client
    # broadcast login to all users except usern
    message = usern + ' logged in'
    broadcast(usern, message, True)

# returns logout_flag and response
def logout(usern, client, is_timeout):
    clients[usern]['status'] = 'logout'
    clients[usern]['socket_and_addr'] = None
    # broadcast logout to all users except usern
    message = usern + ' logged out'
    broadcast(usern, message, True)

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
            clients[usern]['count'] = 0
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
    if check_blocked(usern):
        status = 'ERROR login\n'
        msg = 'Your account is blocked due to multiple login failures. '\
            + 'Please try again later'
        return True, status + msg
    
    clients[usern]['status'] = 'authen'
    if credentials[usern] == passw:
        login(usern, client)
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

# get the list of all online users
def online_users():
    return [usr for usr in clients.keys() if clients[usr]['status'] == 'login']

def whoelse(me):
    all_online_users = online_users()
    other_users = [user for user in all_online_users if user != me]
    status = 'OK whoelse\n'
    msg = '\n'.join(other_users)
    if not other_users:
        msg = 'No one else is online now.'
    return status + msg

def whoelsesince(me, past_time):
    curr_time = datetime.now()
    other_users_since = []
    for user in clients:
        if clients[user]['login_time'] and user != me:
            diff = (curr_time - clients[user]['login_time']).seconds
            if diff <= past_time:
                other_users_since.append(user)
    status = 'OK whoelsesince\n'
    msg = '\n'.join(other_users_since)
    if not other_users_since:
        msg = 'No one else is logged in since ' + str(past_time) + ' seconds ago.'
    return status + msg

# broadcast message and logging information
def broadcast(me, message, is_logging_msg):
    # status pass to receiver
    recv_status = 'OK broadcast\n'
    # status return to the sender
    sender_status = 'OK broadcasted\n'
    sender_msg = ''

    # if not login/logout filter do not send to user who blocked me
    filter_users = clients[me]['blocked_by']
    # if is login/logout broadcast
    if is_logging_msg:
        # do not send logging broadcast to the users I blocked
        filter_users = clients[me]['blocked_users']
        recv_status = 'OK presence\n'
        sender_status = ''

    # send message to each online user except me
    all_online_users = online_users()
    for user in all_online_users:
        if user in filter_users:
            if not is_logging_msg:
                sender_status = 'ERROR broadcast\n'
                sender_msg = 'Your message could not be delivered to some recipients'
        else:
            csocket, _ = clients[user]['socket_and_addr']
            if user != me:
                response = ''
                if is_logging_msg:
                    response += recv_status + message
                else:
                    response += recv_status + me + ': ' + message 
                csocket.send(response.encode())

    return sender_status + sender_msg

# block given user if the user exist, not self, not already blocked
def block(me, block_user):
    status = 'ERROR block\n'
    msg = 'Error. Cannot block nonexistent user'
    if block_user == me:
        msg = 'Error. Cannot block self'
    elif block_user in credentials.keys():
        if block_user in clients[me]['blocked_users']:
            msg = 'Error. You have already blocked ' + block_user
        else:
            clients[me]['blocked_users'].append(block_user)
            for user in clients:
                if user == block_user:
                    clients[user]['blocked_by'].append(me)
            status = 'OK block\n' 
            msg = block_user + ' is blocked'
    return status + msg

# unblock given user if the user exist, not self, is currently blocked
def unblock(me, unblock_user):
    status = 'ERROR unblock\n'
    msg = 'Error. Cannot unblock nonexistent user'
    if unblock_user == me:
        msg = 'Error. Cannot unblock self'
    elif unblock_user in credentials.keys():
        if unblock_user in clients[me]['blocked_users']:
            clients[me]['blocked_users'].remove(unblock_user)
            for user in clients:
                if user == unblock_user:
                    clients[user]['blocked_by'].remove(me)
            status = 'OK unblock\n' 
            msg = unblock_user + ' is unblocked'
        else:
            msg = 'Error. ' + unblock_user + ' was not blocked.'
    return status + msg

# sender msg to receiver if online, else add to offline msg list
def send_msg(sender, receiver, msg):
    # receiver is invalid, either sender itself or not found
    sender_status = 'ERROR message\n'
    sender_msg = 'Error. Invalid user'
    if receiver == sender:
        sender_msg = 'Error. Cannot send message to self'
    elif receiver in credentials.keys():
        if receiver in clients[sender]['blocked_by']:
            sender_msg = 'Your message could not be delivered as the '\
                + 'recipient has blocked you'
        else:
            recv_msg = 'RECV message\n' + sender + ': ' + msg
            if clients[receiver]['status'] == 'login':
                csocket, _ = clients[receiver]['socket_and_addr']
                csocket.send(recv_msg.encode())
            else:
                clients[receiver]['offline_msg'].append(recv_msg)
            sender_status = 'OK message\n'
            sender_msg = ''
    return sender_status + sender_msg

# returns logout_flag and response
def get_response(request, usern, client):
    tokens = request.split()
    if len(tokens) == 3 and tokens[0] == 'authenticate':
        if tokens[1] == 'Username':
            return authen_usern(tokens[2], client)
        elif tokens[1] == 'Password':
            return authen_passw(tokens[2], usern, client)
    if len(tokens) > 3 and tokens[0] == 'authenticate':
        status = 'authenticate ' + tokens[1] + '\n'
        msg = 'Invalid ' + tokens[1] + '. Please try again.'
        return False, status + msg

    if len(tokens) == 1:
        if tokens[0] == 'whoelse':
            return False, whoelse(usern)
        elif tokens[0] == 'logout':
            return logout(usern, client, False)

    if len(tokens) >= 2 and tokens[0] == 'broadcast':
        _, msg = request.split(' ', 1)
        return False, broadcast(usern, msg, False)

    if len(tokens) == 2:
        if tokens[0] == 'whoelsesince':
            try:
                past_time = int(tokens[1])
                return False, whoelsesince(usern, past_time)
            except:
                # if second parameter not integer, invalid command 
                pass
        elif tokens[0] == 'block':
            return False, block(usern, tokens[1])
        elif tokens[0] == 'unblock':
            return False, unblock(usern, tokens[1])

    if len(tokens) >= 3 and tokens[0] == 'message':
        _, receiver, msg = request.split(' ', 2)
        return False, send_msg(usern, receiver, msg)

    status = 'ERROR command\n'
    msg = 'Error. Invalid command'
    return False, status + msg

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
        #debug:
        print('request: ', request)
        if usern and clients[usern]['status'] == 'login':
            clients[usern]['last_activate_time'] = datetime.now()
        logout_flag, response = get_response(request, usern, client)
        
        if response:
            #debug:
            print('response: ', response)
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
            all_online_users = online_users()
            for usern in all_online_users:
                client = clients[usern]['socket_and_addr']
                client_socket, _ = client
                # client has timeout due to inactivity
                diff = datetime.now() - clients[usern]['last_activate_time']
                if diff.seconds >= timeout:
                    _, msg = logout(usern, client, True)
                    # send timeout logout msg to client
                    client_socket.send(msg.encode())
                    # remove logged out client from addr_to_user dict
                    addr_to_user.pop(client, None)
                    # for debug
                    print('closing connection: ', client)
                    # close conn
                    client_socket.close()
                else:
                    # if client not timeout, send offline msg if there is
                    for msg in clients[usern]['offline_msg']:
                        client_socket.send(msg.encode())
                    clients[usern]['offline_msg'] = []

            t_lock.notify()
        # sleep for 1s
        time.sleep(UPDATE_INTERVAL)

def main():
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

    global clients, addr_to_user
    # Store clients info in clients = {username: user_info_dict}
    # 'client_addr' in clients not yet used
    user_info_keys = ['login_time', 'last_activate_time', 'blocked_time'
        'socket_and_addr']
    clients = dict.fromkeys(credentials.keys())
    for usern in clients:
        clients[usern] = dict.fromkeys(user_info_keys)
        # store offline messages
        clients[usern]['offline_msg'] = []
        clients[usern]['blocked_users'] = []
        clients[usern]['blocked_by'] = []
        clients[usern]['status'] = 'logout'

    # addr_to_user = {(client_socket, client_addr): username}
    addr_to_user = {}

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
