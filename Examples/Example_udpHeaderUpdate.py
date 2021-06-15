# -*- coding: utf-8 -*-
"""
Created on Fri Feb 21 16:36:35 2020

@author: dxu
"""



import Fuzz
from Fuzz.Packet_IO.packetIO import packetIO
from Fuzz.Transform_Operation.Header_Update.headerUpdate import headerUpdate

pi = packetIO('../Data/2019-01-21-Emotet-infection-with-Gootkit.pcap')
packets = pi.readPackets()



thu = headerUpdate(['UDP', '10.1.21.101', '10.1.21.1', 61089, 53], 
                      packets, ['dport'],[53], [7070])

thu.operate()








