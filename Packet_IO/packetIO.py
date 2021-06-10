# -*- coding: utf-8 -*-
"""
Created on Wed Aug 12 22:59:12 2020

@author: zhenn
"""
import sys
import scapy
from scapy.all import *


class packetIO(object):
    """
    Apply different packetIO operations.
    """
    def __init__(self,file): 
        self.file = file      
                
        
    def validate(self):
        pass

        
    def replay(self):
        sendp(rdpcap(self.file))
        
    def readPackets(self):
        """
        Read packets from pcap file. 
        """
        __packets = rdpcap(self.file)
        return __packets
  
    
        