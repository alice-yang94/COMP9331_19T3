#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys      
import socket 

def main():
    # Create a TCP socket object(streaming)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)         
    port = int(sys.argv[1])     # Obtain the port no. from command line argument
    s.bind(('localhost', port)) # Bind localhost and port with our socket
    
    # Wait for client connection, queue up to 1 connect request
    s.listen(1)  
               
    while True:
        clientSocket, addr = s.accept()     # Establish connection with client.
        # For debug: print('Got connection from', addr)
       
        # Get the request data
        request = clientSocket.recv(1024).decode()
        # For debug: 
        print('request: ', request)

        # Sometimes Chrome send empty request between certain requests, in order to
        # avoid errors, check if GET is in the request first
        if 'GET' in request:
            # Parse the request string and find the requested file name
            getIndex = request.index('GET')
            filename = request[getIndex+5:].split(' ')[0]

            # For debug: 
            print('Requested file: ', filename)
            try:
                fileContent = ''
                # 'rb' is specified to read the file in binary, so that if the request
                # file is an image, there won't be decoding problem
                f = open(filename, 'rb')
                fileContent = f.read()

                print('sending...')
            
                # send the OK status and content back to the client
                clientSocket.send('HTTP/1.1 200 OK\r\n\r\n'.encode())
                
                clientSocket.send(fileContent)
                clientSocket.close()                # Close the connection
            except FileNotFoundError:
                # if filename not found, reply 404 not found to client
                clientSocket.send('HTTP/1.1 404 Not Found\r\n\r\n'.encode())
                clientSocket.send('404 Not Found\n'.encode())
                clientSocket.close()
           
           
if __name__ == "__main__":
    main()
