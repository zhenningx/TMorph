# -*- coding: utf-8 -*-
"""
Created on Wed Apr 29 18:15:19 2020

@author: dxu
"""

import Fuzz
from Fuzz.Packet_IO.packetIO import packetIO
import Fuzz.Transform_Operation.Tunneling.ipTunneling
from Fuzz.Transform_Operation.Tunneling.ipTunneling import ipTunneling
pi = packetIO('../Data/2019-09-25-Trickbot-gtag-ono19-infection-traffic.pcap')
packets = pi.readPackets()
key = b'49512d4234336164676a7a7a46773374'
iv = b'X\xfe\xd1\xf1\xd1\xdf\x99\xfc\xb0\xe3F\x81\x8d\x13;u'
sip = '1.1.1.1'
dip = '2.2.2.2'
thu = ipTunneling(['TCP', '10.9.25.101', '185.98.87.185', 49197, 80], packets, sip, dip)
thu.operate()