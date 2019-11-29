#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import sys
import socket
from datetime import datetime


def ping(server_socket, seq_no):
    UDP_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    UDP_socket.settimeout(1.0)

    start = datetime.now()
    msg = "PING {} {} \r\n".format(seq_no, start)

    UDP_socket.sendto(msg, server_socket)

    try:
        # input 1024 bytes is the buffer size
        data, addr = UDP_socket.recvfrom(1024)
        rtt = (datetime.now() - start).total_seconds() * 1000

        print('ping to {}, seq = {}, rtt = {} ms'.format(
            server_socket[0], seq_no, rtt))

        return rtt
    except:
        print('ping to {}, seq = {}, time out'.format(
            server_socket[0], seq_no))

        return None


def main():
    args = sys.argv

    if len(args) != 3:
        print('Usage: ' + args[0] + ' host port')
        sys.exit(1)

    UDP_HOST = args[1]
    UDP_PORT = int(args[2])
    server_socket = (UDP_HOST, UDP_PORT)

    rtts = []

    for seq_no in range(10):
        rtt = ping(server_socket, seq_no)
        if rtt is not None:
            rtts.append(rtt)

    if rtts:
        print("round-trip min/avg/max = {}/{}/{} ms".format(
              min(rtts), sum(rtts)/len(rtts), max(rtts)))


if __name__ == "__main__":
    main()
