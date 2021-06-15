# -*- coding: utf-8 -*-
"""
Created on Fri Feb 21 16:36:35 2020

@author: dxu
"""



import Fuzz
from Fuzz.Packet_IO.packetIO import packetIO
import Fuzz.Transform_Operation.Header_Update.headerUpdate
from Fuzz.Transform_Operation.Header_Update.headerUpdate import headerUpdate
pi = packetIO('../Data/weblocal.pcap')
packets = pi.readPackets()



thu = headerUpdate(['HTTP', '192.168.55.3', '192.168.55.5', 43167, 80], 
                      packets, ['User_Agent'], ['curl/7.22.0 (i686-pc-linux-gnu) libcurl/7.22.0 OpenSSL/1.0.1 zlib/1.2.3.4 libidn/1.23 librtmp/2.3'], 
                      ['Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko'])

thu.operate()








