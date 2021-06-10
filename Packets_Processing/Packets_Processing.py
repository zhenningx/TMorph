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

  
#  def readPackets(self, inputFile):
#    """
#    Read packets from pcap file. 
#    """
#    __packets = rdpcap(inputFile)
#    return __packets

  def sortPackets(self, p, opt=None):
    """
    Sort packets by protocol, source port, dest port, source IP, dest IP.
    """
    __sess = "Other"
    
    if opt is not None:
        if opt == 'IP':
            if 'TCP' in p:
                __sess = str(sorted(["IP", p[IP].src, p[TCP].sport, p[IP].dst,
                                     p[TCP].dport],key=str))
            elif 'UDP' in p:
                __sess = str(sorted(["IP", p[IP].src, p[UDP].sport, p[IP].dst,
                                     p[UDP].dport],key=str))
        return __sess
             
    
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
                __sess = str(sorted(["IP", p[IP].src, p[IP].dst, 
                                     p[IP].proto],key=str))
        elif 'ARP' in p:
            __sess = str(sorted(["ARP", p[ARP].psrc, p[ARP].pdst]))
        else:
            __sess = p.sprintf("Ethernet type = %04xr,Ether.type%")
        return __sess
    

       
        

  def filterPackets(self, inputSession, packets):
    """
    Filter packets based on inputSession 
    """
    __filtered = (pkt for pkt in packets if inputSession[0] in pkt and
    (pkt[TCP].sport in inputSession[3:5] and pkt[TCP].dport in inputSession[3:5])
    and (pkt[IP].src in inputSession[1:3] and pkt[IP].dst in inputSession[1:3]))
    return __filtered

  def updateSeqAck(self, inputSession, pkts, updateList):
      """
      Update SEQ and ACK nums for a session. The updateList contains the start
      packet number, the number to change SEQ and ACK, and the source IP of the
      packet whose payload size was changed.
      """

      i = 0
      for pkt in pkts:
          if str(sorted(inputSession,key=str)).split(',')[0:4] == self.sortPackets(pkt).split(',')[0:4]:
              for j in range(len(updateList)):
                  if i > updateList[j][0]:
                      if pkt['IP'].src == inputSession[1]:
                          pkt.seq += updateList[j][1]
                          pkt.ack += updateList[j][2]
                      elif pkt['IP'].dst == inputSession[1]:
                          pkt.seq += updateList[j][2]
                          pkt.ack += updateList[j][1]
                      break
              i += 1
          #     seqAdd = 0
          #     ackAdd = 0
          #     for j in range(len(updateList)):
          #         if i > updateList[j][0]:
          #             if pkt['IP'].src == updateList[j][2]:
          #                seqAdd += updateList[j][1]
          #             elif pkt['IP'].dst == updateList[j][2]:
          #                ackAdd += updateList[j][1]
          #         else:
          #             break
          #     pkt.seq += seqAdd
          #     pkt.ack += ackAdd
          # i += 1
      return (pkts)
      # wrpcap("update.pcap", pkts)
                    

      
  def buildClientPacket(self, sether, dether, sip, dip, ipFlags, ttl, proto,
                        sport, dport, tcpFlags, clientWindow, load):
      """
      Build client side packet of a TCP flow.
      """
      from Fuzz.Transform_Operation.Tunneling.sshTunnelingAESCTR import sshTunneling
      
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
      sshTunneling.clientId = (sshTunneling.clientId + 1)%65535
      return (pktnew)
      # wrpcap("update.pcap",pktnew,append=True)
      
      
  def buildServerPacket(self, sether, dether, sip, dip, ipFlags, ttl, proto,
                            sport, dport, tcpFlags, serverWindow, load):
        """
        Build client side packet of a TCP flow.
        """
        from Fuzz.Transform_Operation.Tunneling.sshTunnelingAESCTR import sshTunneling
        
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
        # pktnew['IP'].len = len(pktnew['IP'])
        pktnew['IP'].chksum = None
        pktnew['TCP'].chksum = None
        sshTunneling.serverSEQ = sshTunneling.serverSEQ + loadSize
        sshTunneling.clientACK = sshTunneling.clientACK + loadSize      
        sshTunneling.serverId = (sshTunneling.serverId + 1)%65535
        return (pktnew)
        # wrpcap("update.pcap",pktnew,append=True)
        
  def buildNewPacket(self, pkt):
       __pktn=Ether()
       layers = pkt.layers()
       for l in layers:
           if l != scapy.layers.l2.Ether:
               __pktn = __pktn/l()
       for l in layers:
           if l != scapy.packet.Raw:
               for f in pkt[l].fields_desc:
                   __pktn.setfieldval((f.name),pkt.getfieldval(f.name))
       __pktn['IP'].src = pkt['IP'].src
       __pktn['IP'].dst = pkt['IP'].dst
       if pkt.haslayer('TCP'):
           __pktn['TCP'].flags = pkt['TCP'].flags
           __pktn['TCP'].options = pkt['TCP'].options
       return __pktn
    
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
                
      



