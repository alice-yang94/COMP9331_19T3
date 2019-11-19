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
    if user_to_conn in conns and conns[user_to_conn]['state']:
        print('Error. You have already connected with ' + user_to_conn)
    else:
        try:
            # set up a new private client socket and connect to private addr
            privClientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            privClientSocket.connect(private_addr)
            privClientSocket.setblocking(False)

            # store the client socket for recv data from socket later
            clientSockets[privClientSocket]['username'] = user_to_conn
            clientSockets[privClientSocket]['addr_and_port'] = private_addr

            # {username: {'socket':privClientSocket, 'state': True for active} }
            conns[user_to_conn]['socket'] = privClientSocket
            conns[user_to_conn]['state'] = True
        except:
            print('Error. {} is offline'.format(user_to_conn))
    return

def set_username(username, curr_socket):
    clientSockets[curr_socket] = username
    # set conns info
    conns[username]['socket'] = curr_socket
    conns[username]['state'] = True

def prepare_to_logout():
    # send msg to all connected private sockets
    conn_users = list(conns.keys())
    for user in conn_users:
        if user != 'original server' and conns[user]['state']:
            user_socket = conns[user]['socket']
            logout_status = 'logoutprivate ' + my_name + '\n'
            user_socket.send(logout_status.encode())
            conns.pop(user, None)

# handle the data received from the curr_socket(can be server or any users)
def data_handler(data, curr_socket):
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
        if status[1] == 'login':
            curr_state = status[1]
        elif status[1] == 'logout':
            prepare_to_logout()
            curr_state = status[1]
        elif status[1] == 'startprivate':
            user_to_conn = status[2]
            private_addr = (status[3], int(status[4]))
            initiate_priv_conn(user_to_conn, private_addr)
        elif status[1] == 'connected':
            return 'my_name ' + my_name + '\n'
        elif status[1] == 'stopprivate':
            # user replied for the stopprivate I initiated, rm user socket
            clientSockets.pop(curr_socket, None)
            curr_socket.close()

    # logout if received timeout msg from server due to inactivity
    # or account blocked due to multiple attempts of wrong passwords
    elif status[0] == 'TIMEOUT' \
        or (status[0] == 'ERROR' and status[1] == 'login'):
        curr_state = 'logout'
    
    elif status[0] == 'my_name':
        set_username(status[1], curr_socket)
    
    elif status[0] == 'logoutprivate':
        # remove user logged out from each list
        user_loggedout = status[1]
        conns[user_loggedout]['state'] = False
        clientSockets.pop(curr_socket, None)
        curr_socket.close()
    
    elif status[0] == 'stopprivatefrom':
        # user wish to stop private conn with me
        user_want_stop = status[1]
        # remove user from conns and clientsockets
        conns.pop(user_want_stop, None)
        clientSockets.pop(curr_socket, None)
        curr_socket.close()
        return 'OK stopprivate ' + my_name + '\n'

    # all other status is used for debugging, no respond needed
    return ''

# accept the private connections with other users as a server
def private_conn_handler():
    while curr_state != 'logout':
        if curr_state == 'login':
            try:
                # Establish connection with another user.
                user_socket, user_addr = privServerSocket.accept()
                # set client socket to non blocking
                user_socket.setblocking(False)

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


# examine request, find socket that the request should goes to
def request_deliver(request):
    # return False if send nothing to any socket
    no_request = False, False
    if request:
        tokens = request.split()
        receiver = 'original server'
        socket = conns['original server']['socket']
        if tokens[0] == 'startprivate':
            return request, socket

        elif tokens[0] == 'private':
            # private receiver msg
            if len(tokens) > 2:    
                _, receiver, msg = request.split(' ', 2)
                if receiver in conns.keys():
                    if conns[receiver]['state']:
                        socket = conns[receiver]['socket']
                        request += '\n{}(private): {}'.format(my_name, msg)
                        return request, socket
                    else:
                        # private conn started but receiver is offline now
                        print(f'Cannot deliver message to {receiver},' \
                                + f' {receiver} is offline now')
                elif receiver == my_name:
                    print('Error. Cannot send private message to self')
                else:
                    print('Error. Private messaging to {} not enabled'.format(receiver))
            elif len(tokens) == 2:
                print('Error. Empty message')
            else:
                print('Error. Invalid command')
            return no_request
            
        elif tokens[0] == 'stopprivate':
            if len(tokens) == 2:
                # tell user to i'm closing the socket
                user_to_stop = tokens[1]
                socket = conns[user_to_stop]['socket']
                conns.pop(user_to_stop, None)
                print('Stop private messaging with ' + user_to_stop)
                request = 'stopprivatefrom ' + my_name + '\n'
                return request, socket
            else:
                print('Error. Invalid command')

            return no_request
        
        return request, socket

    # if request is empty
    print('Error. Empty command')
    return no_request


# thread that handle console input and send to corresponding socket
def input_handler():
    while curr_state != 'logout':
        with t_lock:
            # if login and there is input, send it to server, else continue
            if curr_state == 'login' \
                and sys.stdin in select.select([sys.stdin], [], [], 0)[0]:
                # remove newline by [:-1]
                request = sys.stdin.readline()[:-1]
                request, socket = request_deliver(request)
                if request:
                    socket.send(request.encode())
            t_lock.notify()


# handle data received from all sockets(including server and private users)
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
                        response = data_handler(data, curr_socket)
                        if curr_state != 'logout' and response:
                            curr_socket.send(response.encode())
                except:
                    pass
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
    # {username: {'socket':clientSocket, 'state': offline/active} }
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
    
    # 3 daemon threads for receiving message from clients and server,
    # accepting private connections
    # handling user input and send to correct socket
    recv_thread=threading.Thread(name = "recvHandler",target = recv_handler)
    recv_thread.daemon=True
    recv_thread.start()
    
    priv_conn_thread = threading.Thread(name = "privConnHandler", target = private_conn_handler)
    priv_conn_thread.daemon = True
    priv_conn_thread.start()

    input_thread=threading.Thread(name = "inputHandler",target = input_handler)
    input_thread.daemon=True
    input_thread.start()
    
    # program stop when user is logged out
    while curr_state != 'logout':
        time.sleep(0.1)
    
           
if __name__ == "__main__":
    main()
