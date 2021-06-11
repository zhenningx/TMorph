# -*- coding: utf-8 -*-
"""
Created on Sat Aug 15 10:20:17 2020

@author: zhenn
"""

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



class duplicatePacket(Transform_Operation):
    """
    Duplicates packet accroding to TCP flags.
    """
    def __init__(self, inputSession, packets, flags=None, num=0):
        super().__init__(inputSession, packets)
        self.flags = flags
        self.num = num
                
    def validate(self):
        super().validate()
        
    def operate(self):
        self.validate()
        pp = Packets_Processing()
        for pkt in self.packets:
            c = pp.sortPackets(pkt)
            if (c == str(sorted(self.inputSession,key=str))):
                if self.flags is not None:
                    #sort the flags as the pkt['TCP'].flags maybe 'FS' and user input maybe 'SF'.
                    if str(sorted(pkt['TCP'].flags,key=str)) == str(sorted(self.flags,key=str)):
                        for i in range(self.num):
                            pktn = pp.buildNewPacket(pkt)
                            #cannot use +=1 else all packet's seq is still the same. 
#                            pktn.seq += i
#                            pktn['IP'].len = len(pktn['IP'])
#                            pktn['IP'].chksum = None
#                            pktn['TCP'].chksum = None
                            wrpcap("update.pcap",pktn,append=True)
                    else:
                        wrpcap("update.pcap",pkt,append=True)
                else:
                    wrpcap("update.pcap",pkt,append=True)
            else:
                wrpcap("update.pcap",pkt,append=True)
                
