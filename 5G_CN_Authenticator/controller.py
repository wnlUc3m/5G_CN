import socket
from threading import Thread
from MmeThread import MmeThread
from scapy.all import *
import sctp

'''
Simple Core Network implementation for research purposes
Authors:
    - Gines Garcia-Aviles
    - @github: https://github.com/GinesGarcia
License:
    - MIT License
'''

HOST = '127.0.0.1'
PORT = 36412
BUFSIZE = 2048
ADDR = (HOST, PORT)
threads = []

socket_serv = sctp.sctpsocket_tcp(socket.AF_INET)
socket_serv.bindx([ADDR])
socket_serv.listen(5)
socket_serv.setblocking(1)
socket_serv.set_adaptation(18)

while True:
    print "Waiting for connections on %s:%s ..." % (HOST, PORT)
    conn_sock, addr = socket_serv.accept()

    thread = MmeThread(conn_sock, addr, HOST, PORT)
    thread.start()
    threads.append(thread)
    
# Wait for all threads to finish
for thread in threads:
    thread.join()

socket_serv.close()

