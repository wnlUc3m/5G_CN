import S1apHandler as s1ap
from scapy.all import *

'''
Simple Core Network implementation for research purposes
Authors:
    - Gines Garcia-Aviles
    - @github: https://github.com/GinesGarcia
License:
    - MIT License
'''

class SctpHandler:
    procedure_handler = {}

    def __init__(self):
        #self.procedure_handler = {0:data_handler}
        self.procedure_handler = {1:"init_handler"}
        #self.procedure_handler[3] = "sack_handler"
        #self.procedure_handler[10] = "cookie_echo_handler"

    def get_handler(self, msg_type):
        return self.procedure_handler[msg_type]

    def data_handler():
        print "data message received"

    def init_handler(self):
        print "init message received"
        reply = Ether()/IP()/SCTP()/SCTPChunkInitAck()


    def sack_handler():
        print "sack message received"

    def cookie_echo_handler():
        print "cookie echo message received"

