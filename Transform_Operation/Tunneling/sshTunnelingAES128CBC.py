# -*- coding: utf-8 -*-
"""
Created on Tue Apr 28 15:07:47 2020

@author: dxu
"""

import random
import Fuzz
import Fuzz.Packets_Processing.Packets_Processing
from Fuzz.Packets_Processing.Packets_Processing import Packets_Processing
import Fuzz.Transform_Operation.Transform_Operation
from Fuzz.Transform_Operation.Transform_Operation import Transform_Operation
import scapy
from scapy.all import *
#from scapy.layers.tls.crypto.cipher_block import Cipher_AES_128_CBC
from scapy.layers.tls.crypto.cipher_block import *
#from scapy.layers.tls.crypto.h_mac import Hmac_SHA
from scapy.layers.tls.crypto.h_mac import *
from cryptography.hazmat.primitives import padding
import binascii


class sshTunneling(Transform_Operation):
    """
    Apply tunneling operation.
    """
    clientSEQ = 0
    clientACK = 0
    serverSEQ = 0
    serverACK = 1  
    clientId = random.randrange(20000,40000)
    serverId = random.randrange(20000,40000)
                 
    def __init__(self, inputSession, packets, key, iv):
        super().__init__(inputSession, packets)
        self.dict = dict
        self.clientHmacSeq = 0
        self.serverHmacSeq = 0
        self.key = key
        self.iv = iv

                
    def validate(self):
        pass
    
    def operate(self):
        clientWindow = random.randrange(7000,8000)
        serverWindow = random.randrange(7000,8000)
        pp = Packets_Processing()
        firstPacket = True
        for pkt in self.packets:
            c = pp.sortPackets(pkt)
            if c == str(sorted(self.inputSession,key=str)):
                if firstPacket:
                    port = random.randrange(10000,60000)
                    sip = pkt['IP'].src
                    dip = pkt['IP'].dst
                    sether = pkt['Ether'].src
                    dether = pkt['Ether'].dst
                    #packet 1
                    ether = Ether(src=sether, dst=dether, type='IPv4')
                    ip = IP(src = sip, dst = dip, ihl=5, tos=0x0, 
                            id=sshTunneling.clientId, flags='DF', frag=0, ttl=128, proto='tcp')
                    tcp = TCP(sport=port, dport=22, seq=sshTunneling.clientSEQ, 
                              ack=sshTunneling.clientACK, flags='S', window=clientWindow, 
                              options=[('MSS', 1460), ('NOP', None), 
                                       ('WScale', 8), ('NOP', None), 
                                       ('NOP', None), ('SAckOK', b'')])
                    pktnew = ether/ip/tcp
                    pktnew['IP'].len = len(pktnew['IP'])
                    pktnew['IP'].chksum = None
                    pktnew['TCP'].chksum = None
                    sshTunneling.clientSEQ += 1
                    sshTunneling.clientACK += 1
                    sshTunneling.clientId += 1
                    wrpcap("update.pcap",pktnew,append=True)
                    #packet 2
                    ether = Ether(src=dether, dst=sether, type='IPv4')
                    ip = IP(src = dip, dst = sip, ihl=5, tos=0x0, 
                            id=0, flags='DF', proto='tcp')
                    tcp = TCP(sport=22, dport=port, seq=sshTunneling.serverSEQ, 
                              ack=sshTunneling.serverACK, flags='SA', 
                              window=serverWindow,  
                              options=[('MSS', 1460), ('NOP', None), 
                                       ('WScale', 8), ('NOP', None), 
                                       ('NOP', None), ('SAckOK', b'')])
                    pktnew = ether/ip/tcp
                    pktnew['IP'].len = len(pktnew['IP'])
                    pktnew['IP'].chksum = None
                    pktnew['TCP'].chksum = None
                    sshTunneling.serverSEQ += 1
                    wrpcap("update.pcap",pktnew,append=True)
                    #packet 3
                    ether = Ether(src=sether, dst=dether, type='IPv4')
                    ip = IP(src = sip, dst = dip, ihl=5, tos=0x0, 
                            id=sshTunneling.clientId, flags='DF', proto='tcp')
                    tcp = TCP(sport=port, dport=22, seq=sshTunneling.clientSEQ, 
                              ack=sshTunneling.clientACK,  flags='A', 
                              window=clientWindow)
                    pktnew = ether/ip/tcp
                    pktnew['IP'].len = len(pktnew['IP'])
                    pktnew['IP'].chksum = None
                    pktnew['TCP'].chksum = None
                    sshTunneling.clientId += 1
                    wrpcap("update.pcap",pktnew,append=True)
                    #packet 4
                    load = 'SSH-2.0-PuTTY_Release_0.71\r\n'
                    pp.buildClientPacket(sether,dether,sip, dip, 'DF', 
                        128, 'tcp', port, 22, 'PA', clientWindow, load)
                    #packet 5
                    load = None
                    pp.buildServerPacket(dether,sether,dip, sip, 'DF', 
                        128, 'tcp', 22, port, 'A', serverWindow, load)
                    #packet 6
                    load = 'SSH-2.0-OpenSSH_4.3\n'
                    pp.buildServerPacket(dether,sether,dip, sip, 'DF', 
                        128, 'tcp', 22, port, 'PA', serverWindow, load)
                    #packet 7
                    load = None
                    pp.buildClientPacket(sether,dether,sip, dip, 'DF', 
                        128, 'tcp', port, 22, 'A', clientWindow, load)
                    #packet 8
                    load = b'\x00\x00\x02\xbc\x07\x14\x0c\xf8\x99M3F\xb9\x05}g\x8d\x7f\xf2\x86\x0c\x00\x00\x00\x00Ydiffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1\x00\x00\x00\x0fssh-rsa,ssh-dss\x00\x00\x00\x9daes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se\x00\x00\x00\x9daes128-ctr,aes192-ctr,aes256-ctr,arcfour256,arcfour128,aes128-cbc,3des-cbc,blowfish-cbc,cast128-cbc,aes192-cbc,aes256-cbc,arcfour,rijndael-cbc@lysator.liu.se\x00\x00\x00Uhmac-md5,hmac-sha1,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96\x00\x00\x00Uhmac-md5,hmac-sha1,hmac-ripemd160,hmac-ripemd160@openssh.com,hmac-sha1-96,hmac-md5-96\x00\x00\x00\x15none,zlib@openssh.com\x00\x00\x00\x15none,zlib@openssh.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    pp.buildServerPacket(dether,sether,dip, sip, 'DF', 
                        128, 'tcp', 22, port, 'PA', serverWindow, load)
                    #packet 9
                    load = None
                    pp.buildClientPacket(sether,dether,sip, dip, 'DF', 
                        128, 'tcp', port, 22, 'A', clientWindow, load)
                    #packet 10
                    load = b'\x00\x00\x04\x8c\x04\x14\xb4U\xbf\x86\xa3\xccF\xcf"\xb3r\x19\x10\x00A\x9f\x00\x00\x01\x0ecurve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,diffie-hellman-group-exchange-sha256,diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha256,diffie-hellman-group14-sha1,rsa2048-sha256,rsa1024-sha1,diffie-hellman-group1-sha1\x00\x00\x00Wssh-rsa,ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,ssh-dss\x00\x00\x00\xbdaes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-ctr,aes192-cbc,aes128-ctr,aes128-cbc,chacha20-poly1305@openssh.com,blowfish-ctr,blowfish-cbc,3des-ctr,3des-cbc,arcfour256,arcfour128\x00\x00\x00\xbdaes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-ctr,aes192-cbc,aes128-ctr,aes128-cbc,chacha20-poly1305@openssh.com,blowfish-ctr,blowfish-cbc,3des-ctr,3des-cbc,arcfour256,arcfour128\x00\x00\x00\x9bhmac-sha2-256,hmac-sha1,hmac-sha1-96,hmac-md5,hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha1-96-etm@openssh.com,hmac-md5-etm@openssh.com\x00\x00\x00\x9bhmac-sha2-256,hmac-sha1,hmac-sha1-96,hmac-md5,hmac-sha2-256-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha1-96-etm@openssh.com,hmac-md5-etm@openssh.com\x00\x00\x00\x1anone,zlib,zlib@openssh.com\x00\x00\x00\x1anone,zlib,zlib@openssh.com\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x8d\xca\x05\xd6'
                    pp.buildClientPacket(sether,dether,sip, dip, 'DF', 
                        128, 'tcp', port, 22, 'PA', clientWindow, load)
                    #packet 11
                    load = b'\x00\x00\x00\x14\x06"\x00\x00\x04\x00\x00\x00\x08\x00\x00\x00 \x00\xe9q\xa7\xed\x94p'
                    pp.buildClientPacket(sether,dether,sip, dip, 'DF', 
                        128, 'tcp', port, 22, 'PA', clientWindow, load)
                    #packet 12
                    load = None
                    pp.buildServerPacket(dether,sether,dip, sip, 'DF', 
                        128, 'tcp', 22, port, 'A', serverWindow, load)
                    #packet 13
                    load = b'\x00\x00\x01\x14\x08\x1f\x00\x00\x01\x01\x00\xf8\xf5M\xa4\xe1\xf22\xa9\xd0Q\x04\xb8\x07\xdc\xbe\xa5S\xc1\xe6\x06\xfe\xb1\xcf\x14\x9d\xeb\xb9\x92C\xaa\xa7\xa3Tao\xd9Sh\xeb\xcc\x1aX\xc8\xbc\xb8\x7f\xb9\x93\xf71@\nA>\x07\xe3[\x1a\xdd\xd6HIs\xe1sH5\xfe\xfd\xc2\x14\xda\xca\x8c\x08D(Zg\r\x03\xbb>\x1a[^\x14\xdco; \xea\xac\x8f\x18\xeblH\xaaV\x04\xf2\x1e\xbe\xea<\x86\x7fl\xfa\x01\x08X\xdf\xd5\x89\xdc\xde\xfb\xe8\x99jB\xf5\xba\x00\xbe\xdf\xf6t?MN(\x08\x80ie%\x8cN\x17\xd1\xb2\xbf7\x18\x14ij,\xc7\xc5\xc6T\x8e\xd4\x80\xaat\x91\xa9\xde\x16\xd2\xb1/\x15G\x1b\x19"\x95\xaa\'\xf6\xd0G\xec+\xa7T~\xd7\x06t\xf5+I4\xd8Fq+\x1e\xa8~\x7f\xe1,Z!\r\xef[:\x14\xdb\xc8\xe7\x12\xaaq\x92\xd8w\xb4\xe6G\x9f<\xd6\x9f\x82\x12~sR\xc1\x91\x91\xb06\xa8k\xcf-}|\xc6\x87\xc2\\^F )_\x10\xdc\xcek\xa6jp\xdf\x00\x00\x00\x01\x05\x00\x00\x00\x00\x00\x00\x00\x00'
                    pp.buildServerPacket(dether,sether,dip, sip, 'DF', 
                        128, 'tcp', 22, port, 'PA', serverWindow, load)
                    #packet 14
                    load = b'\x00\x00\x01\x0c\x05 \x00\x00\x01\x01\x00\x9d\xc9O\xf1<\x1eI\xd6\xf8\xb5\xb7\xa1dN\xe8\xc0}\x807\x85\x98\xb6\xea\x93\xc2\xca\xb7\x00\xe9\xa5\xf6\n\xd0\xfaQs\xa1\x1e\xa1\xab\x98l@c\xd3\xcd\xb4\x8d\x955\x17\xed\xc9?\xbdD\x06z\x13\xc6\xec\x0c\x9b\xd5\xc0\x85\x0b\xaf\xe4\x10w}\xbf\x950\xf0/9i\xf3\x10\x04\x04L\x05f\x8f\x17J2\x1f#T\x92\x8dN\xfd\x02\x19\x1a\xc2gq\x8a\xc03~TJ\xc4\x01CvV\xed\xd3?Y\xcf|\xe7\x89\xe9q@K\xf0t\x9c\x8fTG\xd0,\x7f\x9b\x18\xcb0\xdd\x85-X\xaf\x89U\xc8\x9b\xd3\xf9{8\xc4\x9b\xe60^\xea,\xf4\xde\xc1*Qt\x1c\xb8\x88\xfb\xceNo0\x1a\xad\xfam\x84m\xf2\xe0\xdd8\xfc\xf3\xf0\x85Zt\xad\x90;[\xad\n\xe9\xf3\xff\xb3W\x96%\xc9\xb9=\xc0\x8c\x05z~\x90^\x9a\x13\xae\xcf\xf7\xe7\x00\x9f\xad\x99\x88\x01c\xad\n\x1a\xcd^\x8d\x12\xcd\t\xd7\xcd#\x02\xb8}\xbb\xb3tq\x9c\x90\x08A\x9e\xf8\x96\x0b\xa7\x90\x94nrr\x15\xaa\x8f'
                    pp.buildClientPacket(sether,dether,sip, dip, 'DF', 
                        128, 'tcp', port, 22, 'PA', clientWindow, load)
                    #packet 15
                    load = b'\x00\x00\x03<\t!\x00\x00\x01\x15\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x01#\x00\x00\x01\x01\x00\xc8,SP)XU\xb417`\r(\x97\x90\xb6\xa9\xe4\xbc\xc4\x1e\x875II\xc9\x95\x91\\\xc3\nZm\x9d\xa6\x12\x0b\xbc\xa6\x99D\xc2\x8f\x18\xf1t\xf8\xc3T\x92\x002\xd3B\x1b\xd3qi\x16U\xc8g\xca)\xfehP\xa2\xb7"N\x80\xfa\'\x02@\xe5&\xa3J\xe0j\x08\xcc\xa4\x85u\xed\xbb\xb31\r\x07\x9bS~\xab\xed\xa4\xebU\xd8g=>\x86\x87\x9c\xcb\x038\x1e4\x1e\xa0\xc3\xdd\xdb\x98\xa1\x9daU[\x14]\x17\xe78b\xabqU\xcd\xf4\xd93C\xc6\xf8f\xa9\xd0~:\xa4\xa7\xbf\xd1\n\xdeAg\xb4\\\xdaa1 \x8d\xc8S!\x84i64\xc9\xbes-g\x87\x04\x1a4#\'\x8d\xae\xbe\xbe\xc5\xac\xa6t\xf9[)\xc6\x1c8\x8f\x9f\x95\xfb\xb8\xaa\x06+1\n\xa1n\xb9\xd7;\xee\xab\xaa\xac\x1c[\x80I\xc3\xe5?\x10\xc1\xd4E@\xdfo;9\xe2Z\xde\xef\x84v\xb7G\xfbF\xf4\xaa\xf7i\xa6\xcf\x02c\x13\xdeY*\xb3\x9dPW\xd8\x7f\r\x00\x00\x01\x01\x00\x9eN#\xdf\x84t\x9f\x8d{\xf4\xfe\x1a\xb7\x84S\xa9\r(\x16\xc7t\xde\xd0{\xd9>\xd5\x87\x8c\xf6\x03AY\x1d"Rn\x8f\x1e\xfcFX4\xe5\xf8\x82\xb8\xe0/\x98\x9ez\xf2\xe8\xbdJO\x0f\xed\x86\x96H?\x8aN\x88\x9a\x1c4`Y\x91\xa6m\x15\x9f\xaa\x12\xc2\xb8,R|\r\xb9\x8b\x04\xc4\x15\x85\xd4\x17\r\x87\xa9\x19\xf9u\x1dy1\xdc\xc4\x91\xbe\xfd\xcf\xa0\xc6(l\xa7a8\xbfr\xb6\x93\xad\x12CY\xa8\xf2\xf8\xa2x\x08\x84a\xa5\xc2\xba\x11\xffP\xbda\xec\xbb\xd0\x12\xbe6R[3\x9fVEA\xd1\xa1 \xd5\x04\x88\xd1%\x1b$\xd1y\xe5s\xcc\xc7\xd0\xe7\xec;\xfd\xe9\x8d\xd1\x10\xd0>\\%\x0f\xf8\x94(\xdb\xc9\x8b\xebs\xd9/\xc3\xa7\xc5J\xae\xbd\xae?\xbc\xa6v\xba\xd7o\x9a\xae\xb5s\xcd\x98\x96\xa7&\xc8\x99\x1514~\x1b\xb5.\xab\x02U\x9f\x9c\x9eI4\x93\xa2\x14v\xe9\x03\x9b7@\xce\x8bU\x89\x8d\x00<XJ6wp\x8b\x12\xf4\xed\x00\x00\x01\x0f\x00\x00\x00\x07ssh-rsa\x00\x00\x01\x00\xb5nM~\xc1\xa9\xdeX\'\xeb>\x16H\xb3j\x10Xj\xa7\x0c\x0f\x1b\xe2\xb4\x7f\xae\x9e\xfe$\rk\xf6\xcf\xbb\x8eC\xce\xdd\x8b\xdd\x0e\xc5\xaad\xe8\x11\xf1\xa1\x87`\x93\xd5\x7fm\xe3\x87\xe5\xb3|\xa4m\xd9FT\xa4|\x16\x9a\xafPeu\x15}^\x83f\xca\xb1\x8c\n\xf3aB\xb6t\xd0Y\xe2_e"\xb4\xd52\xdf\x19\x8b(\x89z\xb0\xeb\xa3\x83v$\xa6K\x97~\x7f\xe0\x00\xa3\x9e\x04)\xd7\xc6\xe7=\xa7g\x0f,c}\xc3<\x17\x10\x83\xb1\xb9hn\x9d\xd3<\x08\x1baSZ\x86A\xc1\xdb{\xe2v\xacuuK\x82@\x0e\xe4\xb7kR\xdb\x81"}\xe0\x9fx\xc9\r\xab\x92\xfa\xc6\x81\xcd\xf8\x84\x84\xd0\xfe/M2\xa1\x92ce\xa8\x820\x9fz\x9a\x12\x1d\xabto&\x16\x0e*\xfc\xe8\xb6\xa6\x11\xddH[\x17+\x89\xc4AN\xc5\\\xcf\xf5\xbb\n\xf3\xa3\n\'\x13\x83\x01\x8e+\xc3R6\xdef\xdd\t\x18\xcf\xdb\x8a\xf4\xbc1\xda\xe22.13\x14\xcb\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x0c\n\x15\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
                    pp.buildServerPacket(dether,sether,dip, sip, 'DF', 
                        128, 'tcp', 22, port, 'PA', serverWindow, load)
                    #client new key(first 16 bytes of the load) + first
                    #encrypted packet
                    load_new_key = b'\x00\x00\x00\x0c\n\x15\xc8\xc0\x97f\x8f\\Q~{\xfc'
                    load = load_new_key + self.sshLoad(pkt['IP'].payload, self.clientHmacSeq)
                    pp.buildClientPacket(sether,dether,sip, dip, 'DF', 
                        128, 'tcp', port, 22, 'PA', clientWindow, load)
                    self.clientHmacSeq += 1
                    firstPacket = False
                else:
                    sip = pkt['IP'].src
                    dip = pkt['IP'].dst
                    sether = pkt['Ether'].src
                    dether = pkt['Ether'].dst
                    if sip == self.inputSession[1]:
                        load = self.sshLoad(pkt['IP'].payload, self.clientHmacSeq)
                        pp.buildClientPacket(sether,dether,sip, dip, 'DF', 
                        128, 'tcp', port, 22, 'PA', clientWindow, load)
                        self.clientHmacSeq += 1
                        print(self.clientHmacSeq)
                    elif sip == self.inputSession[2]:
                        load = self.sshLoad(pkt['IP'].payload, self.serverHmacSeq)
                        pp.buildServerPacket(sether,dether,sip, dip, 'DF', 
                        128, 'tcp', 22, port, 'PA', serverWindow, load)
                        self.serverHmacSeq += 1
                        print(self.serverHmacSeq)
            else:
                wrpcap("update.pcap",pkt,append=True)
                
    def sshLoad(self, load, hmac_seq):
        """
        Build SSH packet load. 
        Cipher Input: aes128cbc,
        Hmac Input: sha
        """
        #Get the hex of the load size, remove 0x from the begining and 
        #pad 0s to the left to make it 4 bytes.
        packet_length = binascii.unhexlify(hex(len(load))[2:].rjust(8,"0"))
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(packet_length + bytes(load))
        padded_data += padder.finalize()
        encrypted_payload = Cipher_AES_128_CBC(self.key,self.iv).encrypt(padded_data)
        seq_bytes = binascii.unhexlify(hex(hmac_seq)[2:].rjust(8,"0"))
        hmac_load = seq_bytes + bytes(load)
        hmac_digest = Hmac_SHA(self.key).digest(hmac_load)
        sshLoad = encrypted_payload + hmac_digest
        return sshLoad
        
            
        
        
        
        
                
                
#    def buildClientPacket(self, sether, dether, sip, dip, ipFlags, ttl, proto,
#                        sport, dport, tcpFlags, clientWindow, load):
#        """
#        Build client side packet of a TCP flow.
#        """
#        global clientSEQ
#        global serverACK 
#        global clientId
#        print(clientId)
#      
#        ether = Ether(src=sether, dst=dether, type='IPv4')
#        ip = IP(src = sip, dst = dip, ihl=5, tos=0x0, 
#              id=clientId, flags=ipFlags, frag=0, ttl=ttl, proto=proto)
#        tcp = TCP(sport=sport, dport=dport, seq=clientSEQ, 
#                ack=clientACK, flags=tcpFlags, window=clientWindow)
#        if load == None:
#          pktnew = ether/ip/tcp
#          loadSize = 0
#        else:
#          pktnew = ether/ip/tcp/load
#          loadSize = len(load)
#        pktnew['IP'].len = len(pktnew['IP'])
#        pktnew['IP'].chksum = None
#        pktnew['TCP'].chksum = None
#        serverACK = serverACK + loadSize
#        clientSEQ = clientSEQ + loadSize      
#        clientId += 1
#        wrpcap("update.pcap",pktnew,append=True)