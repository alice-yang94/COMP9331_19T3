#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#Usage: python3 client.py server_addr server_port
import socket
import select
import sys
import threading
import time
from collections import defaultdict

# initiate connection with user_to_conn, add user info to private_conns
def initiate_priv_conn(user_to_conn, private_addr):
    if user_to_conn in conns:
        print('Error. You have already connected with ', user_to_conn)
    else:
        try:
            # set up a new private client socket and connect to private addr
            privClientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            print('connect to: ', private_addr)

            privClientSocket.connect(private_addr)
            privClientSocket.setblocking(False)

            # store the client socket for recv data from socket later
            clientSockets[privClientSocket]['username'] = user_to_conn
            clientSockets[privClientSocket]['addr_and_port'] = private_addr

            # {username: {'socket':privClientSocket, 'state': connecting/active} }
            conns[user_to_conn]['socket'] = privClientSocket
            conns[user_to_conn]['state'] = 'active'
        except:
            print('Error. {} is offline'.format(user_to_conn))
    return

# handle the data received from server
def data_handler(data):
    global curr_state, my_name
    status, msg = data.split('\n',1)
    status = status.split()
    if msg:
        print(msg)

    if status[0] == 'authenticate':
        rsp = input(status[1] + ': ')
        # format: authenticate Username/Password xxx
        response =  ' '.join([status[0], status[1], rsp])
        if status[1] == 'Username':
            my_name = rsp
        else:
            # if prompt for password, pass private server address as well
            response += '\n{} {}'.format(privServerName, str(privServerPort))
        return response

    # change current state of client of login/logout
    if status[0] == 'OK':
        if status[1] == 'login' or status[1] == 'logout':
            curr_state = status[1]
        elif status[1] == 'startprivate':
            user_to_conn = status[2]
            private_addr = (status[3], int(status[4]))
            initiate_priv_conn(user_to_conn, private_addr)
        elif status[1] == 'connected':
            return 'my_name ' + my_name
    # logout if received timeout msg from server due to inactivity
    # or account blocked due to multiple attempts of wrong passwords
    elif status[0] == 'TIMEOUT' \
        or (status[0] == 'ERROR' and status[1] == 'login'):
        curr_state = 'logout'

    # all other status is used for debugging, no respond needed
    return ''

# accept the private connections with other users as a server
def private_server_handler():
    while curr_state != 'logout':
        if curr_state == 'login':
            try:
                # Establish connection with another user.
                user_socket, user_addr = privServerSocket.accept()
                # set client socket to non blocking
                user_socket.setblocking(False)
                # For debug: 
                print('Got connection from', user_addr)
                with t_lock:
                    # new connection setup
                    clientSockets[user_socket]['username'] = ''
                    clientSockets[user_socket]['addr_and_port'] = user_addr

                    # confirming connection
                    response_status = 'OK connected\n'
                    response_msg = 'Start private messaging with ' + my_name
                    response = response_status + response_msg
                    # Send the responseStatus and message back to the client
                    user_socket.send(response.encode())

                    # notify the thread waiting
                    t_lock.notify()
            except:
                pass

    # Close the sockets
    if curr_state == 'logout':
        privServerSocket.close()

def set_username(username, curr_socket):
    clientSockets[curr_socket] = username
    # set conns info
    conns[username]['socket'] = curr_socket
    conns[username]['state'] = 'active'

def request_deliver(request, curr_socket):
    # handle request, if request belongs to server, return it
    # else, return False
    if request:
        tokens = request.split()
        
        if tokens[0] == 'startprivate':
            return request
        elif tokens[0] == 'private':
            return False
        elif tokens[0] == 'stopprivate':
            return False
        elif tokens[0] == 'myname':
            set_username(tokens[1], curr_socket)
            return False
        
        return request

    # if request is empty
    print('Error. Empty command')
    return False 


# handle the connection with server
def recv_handler():
    while curr_state != 'logout':
        with t_lock:
            sockets = list(clientSockets.keys())
            for curr_socket in sockets:
                # since curr_socket is non-blocking, use try to recv data, if 
                #nothing received, continue
                try:
                    data = curr_socket.recv(2048).decode()
                    if data:
                        response = data_handler(data).encode()
                        if curr_state != 'logout' and response:
                            curr_socket.send(response)
                except:
                    pass

                # if login and there is input, send it to server, else continue
                if curr_state == 'login' \
                    and sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                    # remove newline by [:-1]
                    request = sys.stdin.readline()[:-1]
                    request = request_deliver(request, curr_socket)
                    if request:
                        curr_socket.send(request.encode())

            t_lock.notify()
    
    with t_lock:
        # Close all sockets if logged out
        for curr_socket in clientSockets.keys():
            curr_socket.close()
        t_lock.notify()

def main():
    global server_address
    # Read server name and port number from command line
    serverName = sys.argv[1]
    serverPort = int(sys.argv[2])
    server_address = (serverName, serverPort)

    # create tcp socket for connecting with server
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # connect to server
    clientSocket.connect(server_address)
    # set sockets to non-blocking
    clientSocket.setblocking(False)

    global privServerSocket, privServerName, privServerPort
    # create tcp sockets for connecting with other users
    privServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    # Bind localhost and port with private server socket
    privServerName = '127.0.0.1'
    privServerSocket.bind((privServerName, 0))
    privServerPort = privServerSocket.getsockname()[1]
    # Wait for client connection, queue up to 10 connect request
    privServerSocket.listen(10)

    # curr_state: authen/login/logout
    global curr_state, my_name, conns, clientSockets
    curr_state = 'authen'
    my_name = ''

    # all connections maintained(once inactive, remove from list): 
    # {username: {'socket':clientSocket, 'state': connecting/active} }
    conn_keys = ['socket', 'state']
    conns = defaultdict(lambda: dict.fromkeys(conn_keys))
    # use original server to avoid same as username (username has no space)
    conns['original server']['socket'] = clientSocket
    conns['original server']['state'] = 'active'

    # set when initiating a private connection
    clientSockets = defaultdict(lambda: dict.fromkeys(['username', 'addr_and_port']))
    clientSockets[clientSocket]['username'] = 'original server'
    clientSockets[clientSocket]['addr_and_port'] = server_address


    global t_lock, UPDATE_INTERVAL
    # threading lock for multiple threads to access shared datastructure
    t_lock = threading.Condition()
    # would communicate with clients after every second
    UPDATE_INTERVAL = 1
    
    recv_thread=threading.Thread(name = "recvHandler",target = recv_handler)
    recv_thread.daemon=True
    recv_thread.start()
    
    priv_server_thread = threading.Thread(name = "privServerHandler", target = private_server_handler)
    priv_server_thread.daemon = True
    priv_server_thread.start()

    #priv_client_thread = threading.Thread(name = "privConnHandler", target = private_client_handler)
    #priv_client_thread.daemon = True
    #priv_client_thread.start()
    
    while curr_state != 'logout':
        time.sleep(0.1)
    
           
if __name__ == "__main__":
    main()
