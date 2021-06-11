# -*- coding: utf-8 -*-
"""
Created on Tue Apr 14 18:34:47 2020

@author: dxu
"""

import Fuzz
from Fuzz.Packet_IO.packetIO import packetIO
from Fuzz.Packets_Processing.Packets_Processing import Packets_Processing
from Fuzz.Transform_Operation.Transform_Operation import Transform_Operation
from Fuzz.Transform_Operation.Header_Update.headerUpdate import headerUpdate
import scapy
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
import scapy.layers.http

class httpHeaderUpdate(headerUpdate):
    """
    Apply HTTP header update.
    """
    def __init__(self, inputSession, packets, fields, oldValues, newValues):
        super().__init__(inputSession, packets, fields, oldValues, newValues)
        print(self.inputSession)
        print("packets in httpheaderUpdate class:")
        self.updateList = []
                        
    def validate(self):
        pass
    
    def operate(self):
        pp = Packets_Processing()
        j = 0
        for pkt in self.packets:
            c = pp.sortPackets(pkt)
            if (c == str(sorted(self.inputSession,key=str)) and 
                pkt.haslayer('HTTP')):
                for i in range(len(self.fields)):
                    # print(self.fields[i])
                    # print(self.oldValues[i])
                    # print(self.newValues[i])
                    #Not all packets in the same session has the field[i],
                    #for ex, not in 200 OK. 
                    #If the packet does not have field[i], 
                    #getfieldval(self.fields[i]) will throw error. If the packet
                    #does not have 'HTTPRequest' in HTTP header, getfieldval 
                    #will fail too. 
                    if 'HTTPRequest' in pkt['HTTP']:
                        if self.fields[i] in pkt['HTTP']['HTTPRequest'].fields:
                            if (pkt.getfieldval(self.fields[i]) == bytes(self.oldValues[i],'utf-8')):
                                pkt.setfieldval(self.fields[i],bytes(self.newValues[i],'utf-8'))
                    if 'HTTPResponse' in pkt['HTTP']:
                        if self.fields[i] in pkt['HTTP']['HTTPResponse'].fields:
                            if (pkt.getfieldval(self.fields[i]) == bytes(self.oldValues[i],'utf-8')):
                                pkt.setfieldval(self.fields[i],bytes(self.newValues[i],'utf-8'))
                self.updateList.append((j,(len(pkt['IP'])-pkt.len),pkt['IP'].src))
                pkt[IP].len = len(pkt['IP'])
                pkt[IP].chksum = None
                pkt[TCP].chksum = None
                wrpcap("update.pcap",pkt,append=True)
                print(self.updateList)
            else:
                wrpcap("update.pcap",pkt,append=True)
            j += 1
#        for r in self.updateList:
#            pp.updateSeqAck(self.inputSession, r)
        pi = packetIO('./update.pcap')
        __packets = pi.readPackets()
        pp.updateSeqAck(self.inputSession, __packets, self.updateList)