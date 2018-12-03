#!/usr/bin/env python3

"""
Bob is another role in the conversationself.

Bob should run the program before Alice.
"""

from User_Class import User

import socket
import os
import sys
import time


bob_host, bob_port = 'localhost', 9200

def reply_conn(conn, addr):
    print('Accept new connection from user {0}'.format(addr));
    #conn.settimeout(500)
    # conn.send(b'Hi, This is bob. Waiting for your sess key')

    conn.close()

Bob = User()

try:
    sock_self = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock_self.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_self.bind((bob_host, bob_port))


except socket.error as msg:
    print(msg);
    sys.exit(1)



while 1:
    sock_self.listen(10)
    print('Waiting for connection...');
    conn, addr = sock_self.accept()
    buf = conn.recv(1024)
    while True:
        try:
            if buf:
                receive_packet = bytes.decode(buf).rstrip('\x00')
                need_rpy, reply_packet, terminal_signal = Bob.respond_state_machine(receive_packet, addr)
                if need_rpy:
                    conn.send(reply_packet.encode())
                if terminal_signal:
                    conn.close()
                    break
                buf = conn.recv(1024)
            else:
                time.sleep(0.5)
        except BrokenPipeError as e:
            print("Alice is angry")
            conn.close()
            break
