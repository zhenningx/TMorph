import sys
import scapy
from scapy import all

class Packet_Processing(object):

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

  
  def __readPackets(self, inputFile):
    """
    Read packets from pcap file. 
    """
    __packets = rdpcap(inputFile)
    return __packets

  def __sortPackets(self, p):
    """
    Sort packets by protocol, source port, dest port, source IP, dest IP.
    """
    __sess = "Other"
    if 'Ether' in p:
        if 'IP' in p:
            if 'TCP' in p:
                __sess = str(sorted(["TCP", p[IP].src, p[TCP].sport, p[IP].dst, p[TCP].dport],key=str))
            elif 'UDP' in p:
                __sess = str(sorted(["UDP", p[IP].src, p[UDP].sport, p[IP].dst, p[UDP].dport],key=str))
            elif 'ICMP' in p:
                __sess = str(sorted(["ICMP", p[IP].src, p[IP].dst, p[ICMP].code, p[ICMP].type, p[ICMP].id],key=str))
            else:
                __sess = str(sorted(["IP", p[IP].src, p[IP].dst, p[IP].proto]))
        elif 'ARP' in p:
            __sess = str(sorted(["ARP", p[ARP].psrc, p[ARP].pdst]))
        else:
            __sess = p.sprintf("Ethernet type = %04xr,Ether.type%")
    return __sess

  def makeBidiSessions(inputFile):
    """
    Extract bidirectional sessions from packets.
    Needs to call __sortPackets(p) function. 
    """
    __packets = self.__readPackets(inputFile)
    __streams = __packets.sessions(__sortPackets)
    return __streams



