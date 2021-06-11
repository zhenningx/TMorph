# -*- coding: utf-8 -*-
"""
Created on Tue Apr 14 18:34:47 2020

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


class ipHeaderUpdate(headerUpdate):
    """
    Apply IP header update.
    """
    def __init__(self, inputSession, packets, fields, oldValues, newValues):
        super().__init__(inputSession, packets, fields, oldValues, newValues)
        print(str(sorted(self.inputSession,key=str)))
        print("packets in ipheaderUpdate class:")
        self.updateList = []
                        
    def validate(self):
        pass
    
    def operate(self):
        pp = Packets_Processing()
        id_incr = 0
        j = 1
        for pkt in self.packets:
            c = pp.sortPackets(pkt,'IP')
            if c == str(sorted(self.inputSession,key=str)):
                for i in range(len(self.fields)):
                    if self.fields[i] == 'src':
                        print(j)
                        print(pkt['IP'].src)
                        if pkt['IP'].src == self.oldValues[i]:
                            pkt['IP'].src = self.newValues[i]
                            print(pkt['IP'].src)
                        elif pkt['IP'].dst == self.oldValues[i]:
                            print(pkt['IP'].dst)
                            pkt['IP'].dst = self.newValues[i]
                            print(pkt['IP'].dst)
                    elif self.fields[i] == 'dst':
                        if pkt['IP'].dst == self.oldValues[i]:
                            pkt['IP'].dst = self.newValues[i]
                        elif pkt['IP'].src == self.oldValues[i]:
                            pkt['IP'].src = self.newValues[i]
                    elif self.fields[i] == 'id':
                        if pkt['IP'].id == self.oldValues[i] + id_incr:
                            pkt['IP'].id = self.newValues[i] + id_incr
                            id_incr += 1
                    elif self.fields[i] in pkt['IP'].fields:
                        if type(self.oldValues[i]) == str:
                            if (pkt.getfieldval(self.fields[i]) == bytes(self.oldValues[i],'utf-8')):
                                pkt.setfieldval(self.fields[i],bytes(self.newValues[i],'utf-8'))
                        else:
                            if pkt.getfieldval(self.fields[i]) == self.oldValues[i]:
                                pkt.setfieldval(self.fields[i],self.newValues[i])
                pkt[IP].chksum = None
                pkt[TCP].chksum = None
                wrpcap("update.pcap",pkt,append=True)
            else:
                wrpcap("update.pcap",pkt,append=True)
            j += 1
