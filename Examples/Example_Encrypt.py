# -*- coding: utf-8 -*-


import timeit
import Fuzz
from Fuzz.Packet_IO.packetIO import packetIO
from Fuzz.Transform_Operation.Encrypt.encryptRC4128 import encryptRC4128
from Fuzz.Transform_Operation.Encrypt.encryptAES import encryptAES
key = b'X\xfe\xd1\xf1\xd1\xdf\x8d\xfc\xb0\xe3F\x81\x8d\x13;uX\xfe\xd1\xf1\xd1\xdf\x8d\xfc\xb0\xe3F\x81\x8d\x13;u'
iv = b'X\xfe\xd1\xf1\xd1\xdf\x99\xfc\xb0\xe3F\x81\x8d\x13;u'

pi = packetIO('../Data/2019-09-25-Trickbot-gtag-ono19-infection-traffic.pcap')
packets = pi.readPackets()

print("completed reading packets")
thu = encryptAES(['TCP','10.9.25.101', '185.98.87.185', 49197, 80], packets, key, iv)

thu.operate()


