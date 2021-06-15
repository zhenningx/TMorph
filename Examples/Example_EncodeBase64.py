# -*- coding: utf-8 -*-
"""
Created on Sun Apr 12 12:46:47 2020

@author: dxu
"""

import cProfile
import Fuzz
from Fuzz.Packet_IO.packetIO import packetIO
from Fuzz.Transform_Operation.Encode.encodeBase64 import encodeBase64
pi = packetIO('../Data/Trickbot-gtag-filtered-1MB.pcap')
packets = pi.readPackets()


thu = encodeBase64(['TCP','10.9.25.101', '185.98.87.185', 49197, 80], packets)

thu.operate()

