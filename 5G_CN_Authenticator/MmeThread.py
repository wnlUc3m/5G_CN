import socket 
import threading 
from SocketServer import ThreadingMixIn
from scapy.all import *
from sctp import *
from pycrate_asn1dir import S1AP
from pycrate_asn1rt.utils import *
import binascii

from S1apHandler import S1apHandler

'''
Simple Core Network implementation for research purposes
Authors:
    - Gines Garcia-Aviles
    - @github: https://github.com/GinesGarcia
License:
    - MIT License
'''

class MmeThread(threading.Thread): 

    BUFSIZE = 2048
    connection_socket = None
    end_point_addr = ""
    
    # Connection peers - ip:port map
    peers = {}


    def __init__(self, socket, client_address, host, listen_port): 
        Thread.__init__(self)
        self. BUFSIZE = 2048
        self.connection_socket = socket
        self.end_point_addr = client_address

        self.stream = 0
 
    def run(self): 

        pool = []
        # TODO: Automatically assign address pool
        if str(self.end_point_addr[0]) == "192.168.10.12":
            print "    [INFO] RAN 1"
            pool.append({'172.0.0.30':True})
        elif str(self.end_point_addr[0]) == "192.168.10.14":
            print "    [INFO] RAN 2"
            pool.append({'172.0.10.30':True})

        self.s1ap = S1apHandler(pool)

        # self.end_point_addr = IP addr + port
        print "[+] New Thread for an incoming packet %s %s" % (str(self.end_point_addr[0]), str(self.end_point_addr[1]))
        print self.end_point_addr
        while True:
            print "[+]--> new msg"

            reception_buffer = bytes()
            reception_buffer = self.connection_socket.recv(4096)

            if not reception_buffer:
                # TODO:
                # if flags == FLAG_NOTIFICATION         --> event notification
                # else if flags != FLAG_NOTIFICATION    --> association is closing
                print 'msg == 0!!'
                break
            else:
                self.peers[self.end_point_addr[0]] = self.end_point_addr[1]
            
                # Transform each character to its hexadecimal representation
                s1ap_pdu = "".join("{:02x}".format(ord(c)) for c in reception_buffer)            
                reply, action = self.s1ap.handle_s1ap_pdu(s1ap_pdu)
                
                if action == 'REPLY':
                    if self.stream == 0:
                        self.connection_socket.sctp_send(reply, stream=0)
                        self.stream = self.stream + 1
                    else:
                        self.connection_socket.sctp_send(reply, stream=1)



    

    

