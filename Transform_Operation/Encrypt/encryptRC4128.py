# -*- coding: utf-8 -*-
"""
Created on Thu Apr 23 22:38:52 2020

@author: dxu
"""

import sys
import Fuzz
from Fuzz.Packets_Processing.Packets_Processing import Packets_Processing
from Fuzz.Transform_Operation.Transform_Operation import Transform_Operation
import scapy
from scapy.all import *
from scapy.utils import RawPcapReader,rdpcap,repr_hex
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.layers.tls.crypto.cipher_stream import Cipher_RC4_128
from cryptography.hazmat.primitives import padding

class encryptRC4128(Transform_Operation):
    """
    Apply encode operation.
    """
    def __init__(self, inputSession, packets, key):
        super().__init__(inputSession, packets)
        self.key = key
                        
    def validate(self):
        super().validate()
        assert type(self.key) == bytes, 'Key must be bytes type'

    
    def operate(self):
        self.validate()
        for pkt in self.packets:
            if (self.inputSession[0] in pkt and 
            pkt[TCP].sport in self.inputSession[3:5] and pkt[TCP].dport in self.inputSession[3:5]
            and pkt[IP].src in self.inputSession[1:3] and pkt[IP].dst in self.inputSession[1:3]):
                if pkt.haslayer(Raw):
                    encrypted_payload = Cipher_RC4_128(self.key).encrypt(pkt.load)
                    pkt.load = encrypted_payload
                    pkt[IP].chksum = None
                    pkt[TCP].chksum = None
                    wrpcap("update.pcap",pkt,append=True)
                else:
                    wrpcap("update.pcap",pkt,append=True)
            else:
                wrpcap("update.pcap",pkt,append=True)


    