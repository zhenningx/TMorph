# -*- coding: utf-8 -*-
"""
Created on Fri Feb 21 16:36:35 2020

@author: dxu
"""



import Fuzz
from Fuzz.Packet_IO.packetIO import packetIO
from Fuzz.Transform_Operation.Header_Update.headerUpdate import headerUpdate


pi = packetIO('../Data/Trickbot-gtag-filtered-1MB.pcap')
packets = pi.readPackets()
    
thu = headerUpdate(['TCP','10.9.25.101', '185.98.87.185', 49197, 80], 
                      packets, ['dport'],[80], [7070])

thu.operate()










