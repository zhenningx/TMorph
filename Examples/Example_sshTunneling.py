# -*- coding: utf-8 -*-
"""
Created on Fri May 15 19:12:42 2020

@author: dxu
"""



import Fuzz
from Fuzz.Packet_IO.packetIO import packetIO
from Fuzz.Packets_Processing.Packets_Processing import Packets_Processing
from Fuzz.Transform_Operation.Tunneling.sshTunnelingAESCTR import sshTunneling

pi = packetIO('../Data/Trickbot-gtag-filtered-1MB.pcap')
packets = pi.readPackets()

key = b'49512d4234336164676a7a7a46773374'

iv = b'X\xfe\xd1\xf1\xd1\xdf\x99\xfc\xb0\xe3F\x81\x8d\x13;u'
thu = sshTunneling(['TCP', '10.9.25.101', '185.98.87.185', 49197, 80], packets, key, iv)
thu.operate()

