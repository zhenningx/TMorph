import sys
import scapy
from scapy.all import *

class Packets_Processing(object):

  """
  Read packets from pcap file into a packet list. Create a session list with all
  the bidirectional sessions in this pcap file. 

  :version:
  :author:
  """

  """ ATTRIBUTES

   

  inputFile  (public)

   

  packets  (private)

   

  """

  
  def readPackets(self, inputFile):
    """
    Read packets from pcap file. 
    """
    __packets = rdpcap(inputFile)
    return __packets

  def sortPackets(self, p):
    """
    Sort packets by protocol, source port, dest port, source IP, dest IP.
    """
    __sess = "Other"
    if 'Ether' in p:
        if 'IP' in p:
            if 'HTTP' in p:
                __sess = str(sorted(["HTTP", p[IP].src, p[TCP].sport, p[IP].dst,
                                     p[TCP].dport],key=str))
            elif 'TCP' in p:
                __sess = str(sorted(["TCP", p[IP].src, p[TCP].sport, p[IP].dst,
                                     p[TCP].dport],key=str))
            elif 'UDP' in p:
                __sess = str(sorted(["UDP", p[IP].src, p[UDP].sport, p[IP].dst,
                                     p[UDP].dport],key=str))
            elif 'ICMP' in p:
                __sess = str(sorted(["ICMP", p[IP].src, p[IP].dst,
                                     p[ICMP].code, p[ICMP].type, p[ICMP].id],
                                     key=str))
            else:
                __sess = str(sorted(["IP", p[IP].src, p[IP].dst, p[IP].proto]))
        elif 'ARP' in p:
            __sess = str(sorted(["ARP", p[ARP].psrc, p[ARP].pdst]))
        else:
            __sess = p.sprintf("Ethernet type = %04xr,Ether.type%")
    return __sess

  def makeBidiSessions(self, inputFile):
    """
    Extract bidirectional sessions from packets.
    Needs to call __sortPackets(p) function. 
    """
    __packets = self.__readPackets(inputFile)
    __streams = __packets.sessions(self.sortPackets)
    return __streams

  def updateSeqAck(self, inputSession, packets, updateList):
      i = 0
      for pkt in packets:
#        print(i)
#        print((i > updateList[0]))
        c = self.sortPackets(pkt)
        # cannot use "if (c == str(sorted(self.inputSession,key=str))" as 
        # protocol in inputSession can be HTTP and TCP in c so they do not 
        # match. 
        if str(sorted(inputSession,key=str)).split(',')[0:4] == self.sortPackets(pkt).split(',')[0:4]:
            if i > updateList[0]:
                print(i)
                print(pkt.seq)
                print(pkt.ack)
                print(pkt['IP'].src)
                if pkt['IP'].src == inputSession[1]:
                    print("Change SEQ")
                    pkt.seq = pkt.seq + updateList[1]
                else:
                    print("Change ACK")
                    pkt.ack = pkt.ack + updateList[1]
                wrpcap("updateSeq.pcap",pkt,append=True)
                print(pkt.seq)
                print(pkt.ack)
            else:
                wrpcap("updateSeq.pcap",pkt,append=True)
        else:
            wrpcap("updateSeq.pcap",pkt,append=True)
        i += 1
    
            



