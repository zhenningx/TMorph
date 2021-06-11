# -*- coding: utf-8 -*-
"""
Created on Tue Apr 28 15:07:47 2020

@author: dxu
"""

import Fuzz
from Fuzz.Packets_Processing.Packets_Processing import Packets_Processing
from Fuzz.Transform_Operation.Transform_Operation import Transform_Operation
import scapy
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
import os
from os import path

class ipTunneling(Transform_Operation):
    """
    Apply tunneling operation.
    """
    def __init__(self, inputSession, packets, sip, dip):
        super().__init__(inputSession, packets)
        self.sip = sip
        self.dip = dip
                
    def validate(self):
        super().validate()
    
    def operate(self):
        self.validate()
        if path.exists("update.pcap"): os.remove("update.pcap") 
        pp = Packets_Processing()
        for pkt in self.packets:
            c = pp.sortPackets(pkt)
            if c == str(sorted(self.inputSession,key=str)):
                ether = Ether(src = pkt['Ether'].src, dst = pkt['Ether'].dst)
                if pkt['IP'].src == self.inputSession[1]:
                    ip = IP(src = self.sip, dst = self.dip, proto = 4)
                else:
                    ip = IP(src = self.dip, dst = self.sip, proto = 4)
                ip.flags = pkt['IP'].flags
                load = pkt['Ether'].payload
                pkt = ether/ip/load
                pkt[IP].chksum = None
                wrpcap("update.pcap",pkt,append=True)
            else:
                wrpcap("update.pcap",pkt,append=True)
