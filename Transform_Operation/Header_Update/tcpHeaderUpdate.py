# -*- coding: utf-8 -*-
"""
Created on Tue Apr 14 18:28:49 2020

@author: dxu
"""

import Fuzz
from Fuzz.Packets_Processing.Packets_Processing import Packets_Processing
from Fuzz.Transform_Operation.Transform_Operation import Transform_Operation
from Fuzz.Transform_Operation.Header_Update.headerUpdate import headerUpdate
import scapy
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
#if doing tcpHeaderUpdate, do not import http layer, otherwise the http
#packets will not be matched as tcp packets. See the sortPackets function
#in Packet_Processing class. 

class tcpHeaderUpdate(headerUpdate):
    """
    Apply TCP header update.
    """
    def __init__(self, inputSession, packets, fields, oldValues, newValues):
        super().__init__(inputSession, packets, fields, oldValues, newValues)
#         self.fields = fields 
#        self.oldValues = oldValues
#        self.newValues = newValues

                        
        
    def operate(self):
        # pp = Packets_Processing()
        for pkt in self.packets:
            # c = pp.sortPackets(pkt)
            # if c == str(sorted(self.inputSession,key=str)):
            if (self.inputSession[0] in pkt and 
            pkt[TCP].sport in self.inputSession[3:5] and pkt[TCP].dport in self.inputSession[3:5]
            and pkt[IP].src in self.inputSession[1:3] and pkt[IP].dst in self.inputSession[1:3]):
                for i in range(len(self.fields)):
                    # print(self.fields[i])
                    # print(self.oldValues[i])
                    # print(self.newValues[i])
                    # print(pkt.getfieldval(self.fields[i]))
                    #When changing port, also change for return packets.
                    if 'port' in self.fields[i]:
                        if pkt.sport == self.oldValues[i]:
                            pkt.sport = self.newValues[i]
                        elif pkt.dport == self.oldValues[i]:
                            pkt.dport = self.newValues[i]
                    #For TCP Flags operation. Getfieldval for flags returns
                    #the IP flags, such as DF. 
                    elif 'flags' in self.fields[i]:
                        if pkt['TCP'].flags == self.oldValues[i]:
                            pkt['TCP'].flags = self.newValues[i]
                    elif self.fields[i] == 'seq':
                        if pkt['IP'].src == self.inputSession[1]:
                            pkt.seq = self.newValues[i] + pkt.seq - self.oldValues[i]
                        elif pkt['IP'].dst == self.inputSession[1]:
                            pkt.ack = self.newValues[i] + pkt.ack - self.oldValues[i]
                    elif pkt.getfieldval(self.fields[i]) == self.oldValues[i]:
                            pkt.setfieldval(self.fields[i],self.newValues[i])
                pkt[IP].chksum = None
                pkt[TCP].chksum = None
            #     wrpcap("update.pcap",pkt,append=True)
            # else:
            #     wrpcap("update.pcap",pkt,append=True)