import sys
import Fuzz
from Fuzz.Packets_Processing.Packets_Processing import Packets_Processing
from Fuzz.Transform_Operation.Transform_Operation import Transform_Operation
from Fuzz.Packet_IO.packetIO import packetIO
import scapy
from scapy.all import *
from scapy.utils import RawPcapReader,rdpcap,repr_hex
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.layers.tls.crypto.cipher_block import Cipher_AES_128_CBC
from scapy.layers.tls.crypto.cipher_block import Cipher_AES_256_CBC
from cryptography.hazmat.primitives import padding


class encryptAES(Transform_Operation):
    """
    Apply encode operation.
    """

    def __init__(self, inputSession, packets, key, iv):
        super().__init__(inputSession, packets)
        self.key = key
        self.iv = iv
        self.updateList = []
  
      
    def validate(self):
        super().validate()
        assert (type(self.key) == bytes) and (type(self.iv) == bytes), 'Key and IV must be bytes type'
        assert len(self.key) in [16,24,32], 'Key length must be 16, 24 or 32 bytes'
        assert len(self.iv) == 16, 'IV length must be 16 bytes'
    

    def operate(self):
        self.validate()
        pp = Packets_Processing()
        srcsum = 0
        dstsum = 0
        for pkt in self.packets:
            if (self.inputSession[0] in pkt and 
            pkt[TCP].sport in self.inputSession[3:5] and pkt[TCP].dport in self.inputSession[3:5]
            and pkt[IP].src in self.inputSession[1:3] and pkt[IP].dst in self.inputSession[1:3]):
                if pkt['IP'].src == self.inputSession[1]:
                    pkt.seq += srcsum
                    pkt.ack += dstsum
                elif pkt['IP'].dst == self.inputSession[1]:
                    pkt.seq += dstsum
                    pkt.ack += srcsum
                if pkt.haslayer(Raw):
                    padder = padding.PKCS7(128).padder()
                    padded_data = padder.update(pkt.load)
                    padded_data += padder.finalize()
                    if len(self.key) == 16:
                        encrypted_payload = Cipher_AES_128_CBC(self.key,self.iv).encrypt(padded_data)
                    elif len(self.key) == 32:
                        encrypted_payload = Cipher_AES_256_CBC(self.key,self.iv).encrypt(padded_data)
                    pktn = pp.buildNewPacket(pkt)
                    pktn.load = encrypted_payload
                    pktn['IP'].len = len(pktn['IP'])
                    pktn['IP'].chksum = None
                    pktn['TCP'].chksum = None
                    pktn['TCP'].flags = pkt['TCP'].flags
                    if pkt['IP'].src == self.inputSession[1]:
                        srcsum += (len(pktn['IP'])-pkt.len)
                    elif pkt['IP'].dst == self.inputSession[1]:
                        dstsum += (len(pktn['IP'])-pkt.len)
                    wrpcap("update.pcap",pktn,append=True)
                else:
                    wrpcap("update.pcap",pkt,append=True)
            else:
                wrpcap("update.pcap",pkt,append=True)

                



    