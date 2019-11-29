#!/usr/bin/env python2
# -*- coding: utf-8 -*-
import sys
#import time
import socket
from datetime import datetime

#https://wiki.python.org/moin/UdpCommunication#Sending
    
def main(argv):
    argc = len(argv)
    if argc != 3:
        print('Usage: ' + argv[0] + ' host port')
        sys.exit()
    
    UDP_HOST = argv[1]
    UDP_PORT = int(argv[2])
    server_address = (UDP_HOST, UDP_PORT)
    
    received_packets_no = 10
    total_rtt = 0.0
    rtt_min = float("inf")
    rtt_max = 0.0 
    rtt_avg = 0.0
    
    for seq_no in range(10):
        # Create a UDP socket
        UDP_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        UDP_socket.settimeout(1.0)
        
        UDP_socket.bind(server_address)
        
        # Send message to server
        start = str(datetime.now())
        msg = 'PING ' + str(seq_no) + ' ' + start + '\r\n'
        UDP_socket.sendto(msg, server_address)    
        
        # Receive message from server
        try:
          
            # input 1024 bytes is the buffer size
            data, addr = UDP_socket.recvfrom(1024)
            rtt = (datetime.now() - start).total_seconds() * 1000
            print('ping to {}, seq = {}, rtt = {} ms'.format(UDP_HOST, seq_no, rtt))
            total_rtt += rtt
            
            if rtt < rtt_min:
                rtt_min = rtt
            if rtt > rtt_max:
                rtt_max = rtt
            
        except socket.timeout:
            received_packets_no -= 1
            print('ping to {}, seq = {}, time out'.format(UDP_HOST, seq_no))
    
    
    if received_packets_no != 0:
        rtt_avg = total_rtt / float(received_packets_no)
    
    print('round-trip min/avg/max = ' + str(rtt_min) + '/' + str(rtt_avg) + \
              '/' + str(rtt_max) +'ms')            
            
    
if __name__ == "__main__":
    main(sys.argv)