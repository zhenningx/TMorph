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
from scapy.layers.inet import IP, UDP
#if doing tcpHeaderUpdate, do not import http layer, otherwise the http
#packets will not be matched as tcp packets. See the sortPackets function
#in Packet_Processing class. 

class udpHeaderUpdate(headerUpdate):
    """
    Apply UDP header update.
    """
    def __init__(self, inputSession, packets, fields, oldValues, newValues):
        super().__init__(inputSession, packets, fields, oldValues, newValues)
#         self.fields = fields 
#        self.oldValues = oldValues
#        self.newValues = newValues
        print(self.inputSession)
        print("packets in tcpheaderUpdate class:")
                        
        
    def operate(self):
        pp = Packets_Processing()
        for pkt in self.packets:
            c = pp.sortPackets(pkt)
            if c == str(sorted(self.inputSession,key=str)):
                print (len(self.fields))
                for i in range(len(self.fields)):
                    print(self.fields[i])
                    print(self.oldValues[i])
                    print(self.newValues[i])
                    print(pkt.getfieldval(self.fields[i]))
                    #When changing port, also change for return packets.
                    if 'port' in self.fields[i]:
                        if pkt.sport == self.oldValues[i]:
                            pkt.sport = self.newValues[i]
                        elif pkt.dport == self.oldValues[i]:
                            pkt.dport = self.newValues[i]
                pkt[IP].chksum = None
                pkt[UDP].chksum = None
                wrpcap("update.pcap",pkt,append=True)
            else:
                wrpcap("update.pcap",pkt,append=True)