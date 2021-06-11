# -*- coding: utf-8 -*-
"""
Created on Thu Apr 16 13:35:44 2020

@author: dxu
"""

import Fuzz
from Fuzz.Packets_Processing.Packets_Processing import Packets_Processing
from Fuzz.Transform_Operation.Transform_Operation import Transform_Operation
import scapy
from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
import base64

class encodeAscii85(Transform_Operation):
    """
    Apply encode operation.
    """
    def __init__(self, inputSession, packets):
        super().__init__(inputSession, packets)
                
    def validate(self):
        super().validate()
        
    def operate(self):
        self.validate()
        for pkt in self.packets:
            c = pp.sortPackets(pkt)
            if (self.inputSession[0] in pkt and 
            pkt[TCP].sport in self.inputSession[3:5] and pkt[TCP].dport in self.inputSession[3:5]
            and pkt[IP].src in self.inputSession[1:3] and pkt[IP].dst in self.inputSession[1:3]):
                if pkt.haslayer(Raw):
                    encoded_payload = base64.a85encode(pkt.load)
                    pkt.load = encoded_payload
                    pkt[IP].chksum = None
                    pkt[IP].chksum = None
                    wrpcap("update.pcap",pkt,append=True)
                else:
                    wrpcap("update.pcap",pkt,append=True)
            else:
                wrpcap("update.pcap",pkt,append=True)