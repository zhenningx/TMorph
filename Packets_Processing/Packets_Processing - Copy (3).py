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
#
#  def makeBidiSessions(self, inputFile):
#    """
#    Extract bidirectional sessions from packets.
#    Needs to call __sortPackets(p) function. 
#    """
#    __packets = self.__readPackets(inputFile)
#    __streams = __packets.sessions(self.sortPackets)
#    return __streams

  def updateSeqAck(self, inputSession, updateList):
      """
      Update SEQ and ACK nums for a session. The updateList contains the start
      packet number and the number to change SEQ and ACK.
      """
      __packets = self.readPackets('./update.pcap')
      i = 0
      print(updateList)
      for pkt in __packets:
        # cannot use "if (c == str(sorted(self.inputSession,key=str))" as 
        # protocol in inputSession can be HTTP and TCP in c so they do not 
        # match. 
        if str(sorted(inputSession,key=str)).split(',')[0:4] == self.sortPackets(pkt).split(',')[0:4]:
            if i > updateList[0]:
                print(i)
                print(pkt['IP'].src)
                if pkt['IP'].src == inputSession[1]:
                    print("Change SEQ")
                    pkt.seq = pkt.seq + updateList[1]
                else:
                    print("Change ACK")
                    pkt.ack = pkt.ack + updateList[1]   
        i += 1
      wrpcap("update.pcap",__packets)
      
  def buildClientPacket(self, sether, dether, sip, dip, ipFlags, ttl, proto,
                        sport, dport, tcpFlags, clientWindow, load):
      """
      Build client side packet of a TCP flow.
      """
      import Fuzz.Transform_Operation.Tunneling.sshTunneling
      from Fuzz.Transform_Operation.Tunneling.sshTunneling import sshTunneling
      
      ether = Ether(src=sether, dst=dether, type='IPv4')
      ip = IP(src = sip, dst = dip, ihl=5, tos=0x0, 
            id=sshTunneling.clientId, flags=ipFlags, frag=0, ttl=ttl, proto=proto)
      tcp = TCP(sport=sport, dport=dport, seq=sshTunneling.clientSEQ, 
              ack=sshTunneling.clientACK, flags=tcpFlags, window=clientWindow)
      if load == None:
        pktnew = ether/ip/tcp
        loadSize = 0
      else:
        pktnew = ether/ip/tcp/load
        loadSize = len(load)
      pktnew['IP'].len = len(pktnew['IP'])
      pktnew['IP'].chksum = None
      pktnew['TCP'].chksum = None
      sshTunneling.serverACK = sshTunneling.serverACK + loadSize
      sshTunneling.clientSEQ = sshTunneling.clientSEQ + loadSize      
      sshTunneling.clientId += 1
      wrpcap("update.pcap",pktnew,append=True)
      
      
    def buildServerPacket(self, sether, dether, sip, dip, ipFlags, ttl, proto,
                            sport, dport, tcpFlags, serverWindow, load):
          """
          Build client side packet of a TCP flow.
          """
          import Fuzz.Transform_Operation.Tunneling.sshTunneling
          from Fuzz.Transform_Operation.Tunneling.sshTunneling import sshTunneling
          
          ether = Ether(src=sether, dst=dether, type='IPv4')
          ip = IP(src = sip, dst = dip, ihl=5, tos=0x0, 
                id=sshTunneling.serverId, flags=ipFlags, frag=0, ttl=ttl, proto=proto)
          tcp = TCP(sport=sport, dport=dport, seq=sshTunneling.serverSEQ, 
                  ack=sshTunneling.serverACK, flags=tcpFlags, window=serverWindow)
          if load == None:
            pktnew = ether/ip/tcp
            loadSize = 0
          else:
            pktnew = ether/ip/tcp/load
            loadSize = len(load)
          pktnew['IP'].len = len(pktnew['IP'])
          pktnew['IP'].chksum = None
          pktnew['TCP'].chksum = None
          sshTunneling.serverSEQ = sshTunneling.serverSEQ + loadSize
          sshTunneling.clientACK = sshTunneling.clientACK + loadSize      
          sshTunneling.serverId += 1
          wrpcap("update.pcap",pktnew,append=True)
    
#  def shiftPackets(self, inputSession, packets, num):
#      """
#      Shift packets down for "num" of positions, starting from the
#      first packet in inputSession.
#      """
#      __packets = packets
#      i = 0
#      for pkt in __packets:
#            c = self.sortPackets(pkt)
#            if c == str(sorted(self.inputSession,key=str)):
#                break
#            else:
#                i += 1
#      
                
      


