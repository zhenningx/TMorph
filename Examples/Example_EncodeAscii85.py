# -*- coding: utf-8 -*-
"""
Created on Sun Apr 12 12:46:47 2020

@author: dxu
"""

import Fuzz
from Fuzz.Packet_IO.packetIO import packetIO
from Fuzz.Transform_Operation.Encode.encodeAscii85 import encodeAscii85
pi = packetIO('../Data/2019-09-25-Trickbot-gtag-ono19-infection-traffic.pcap')
packets = pi.readPackets()

print("completed reading packets")


thu = encodeAscii85(['TCP','10.9.25.101', '185.98.87.185', 49197, 80], packets)

thu.operate()