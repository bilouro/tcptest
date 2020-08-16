# Copyright (c) 2008, Victor Hugo Bilouro
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
# Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the
# documentation and/or other materials provided with the distribution.
#
# Neither the name of Victor Hugo Bilouro nor the names of its 
# contributors may be used to endorse or promote products derived from 
# this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Author: Victor Hugo Bilouro 
#
# Description: A simple test of three way handshake without any changes 
#

import unittest 
from pcs.packets import ipv4
from pcs.packets import tcp
from pcs.packets import ethernet
import pcs

class TestThreeWayHandshakeWithoutAnyOptions(unittest.TestCase):
    """This class tests the threeway handshake without any options"""

    def setUp(self):
        """
        As it's the first test, I will use this method as a simple TCB.
        I'm planning use some object to handle that.
        
        In this version, TCB is being initialized with test setup 
        values.
        
        Tcpdump file format would a form to store setup values.        
        """
        import random
        
        self.tcb = self

        #constants
        self.thisside = 0
        self.thatside = 1
        #...Can add other sides
        
        #opt 1 - this opt reduce the scalability, and bring more code.
        #self.ipsrc = pcs.inet_atol("192.168.1.10")
        #self.ipdst = pcs.inet_atol("192.168.1.20")
        #opt 2
        self.ip = { self.thisside : pcs.inet_atol("10.211.55.210") , \
                    self.thatside : pcs.inet_atol("10.211.55.220")}

        self.ipid = { self.thisside : random.randrange(1,(1<<16)-1) , \
                      self.thatside : 0}


        self.tcpport = { self.thisside : random.randrange(50000,60000) , \
                         self.thatside : 9}

        self.tcpsequence = { self.thisside : random.randrange(1,(1<<32)-1) , 
                             self.thatside : 0}
        
        # see TODO       
        self.ether = \
                { self.thisside : ethernet.ether_atob("00:1c:42:9d:57:c9") , \
                  self.thatside : ethernet.ether_atob("00:1c:42:db:c5:22") }


        # see TODO       
        self.output = { self.thisside : pcs.PcapConnector("ed0") ,\
                        self.thatside : pcs.PcapConnector("ed0") } 


    def testTestThreeWayHandshakeWithoutAnyOptions(self):
        """active open - three way handshake"""
        #RFC793-P31-p1
        #Reference to 3way handshake
        
    #
    #Sendind SYN
    #
        #THISSIDE
        (ipsyn, tcpsyn) = createsyn(self, self.tcb, self.tcb.thisside, \
						      self.tcb.thatside)
        createwritepacket(self, self.tcb, ipsyn, tcpsyn, self.tcb.thisside, \
                                                           self.tcb.thatside)

        #THATHSIDE
        #Receiving SYN (unfurtunately this time we are receiving from 
	#the same board) 
        (ipsynreceived, tcpsynreceived) = receive(self, self.tcb, self.tcb.thatside, \
                                                                    self.tcb.thisside)

        self.assertEqual(ipsyn, ipsynreceived)
        self.assertEqual(tcpsyn, tcpsynreceived)
        print tcpsynreceived 


    #
    #Receiving SYN+ACK
    #
        #THISSIDE
        #Receivinig SYN + ACK
        (ipsynack, tcpsynack) = receive(self, self.tcb, self.tcb.thisside, \
							   self.tcb.thatside) 

	#Some blackmagic to use assertSequenceAcknowledgmentOK at SYN
        self.tcb.tcpsequence[ self.tcb.thatside ] = tcpsynack.sequence  
        assertSequenceAcknowledgmentOK(self, self.tcb, tcpsynack, \
					self.tcb.thisside, self.tcb.thatside)

	assertSynPresent(self, tcpsynack)

        #OK Its a SYN+ACK --> SYN consumes a sequence
        self.tcb.tcpsequence[ self.tcb.thatside ] = tcpsynack.sequence + 1
        print tcpsynack 


    #
    #Sending ACK
    #
        #THISSIDE
        (ipack, tcpack) = createip(self, self.tcb, self.tcb.thisside, \
						     self.tcb.thatside)

        createwritepacket(self, self.tcb, ipack, tcpack, self.tcb.thisside, \
                                                           self.tcb.thatside)
        print tcpack 

        #THATHSIDE
        #Receiving SYN (unfurtunately this time we are receiving from the same board) 
        (ipackreceived, tcpackreceived) = receive(self, self.tcb, self.tcb.thatside, \
                                                                    self.tcb.thisside)
        #Different values then 0 and 1 to tcpflags TODO
        #self.assertEqual(ipack, ipackreceived)
        #self.assertEqual(tcpack, tcpackreceived)


    #
    #Sending FIN
    #
        #THISSIDE
        (ipfin, tcpfin) = createfin(self, self.tcb, self.tcb.thisside, self.tcb.thatside)
        createwritepacket(self, self.tcb, ipfin, tcpfin, self.tcb.thisside, \
                                                           self.tcb.thatside)
        print tcpfin 

        #THATHSIDE
        #Receiving SYN (unfurtunately this time we are receiving from the same board) 
        (ipfinreceived, tcpfinreceived) = receive(self, self.tcb, self.tcb.thatside, \
                                                                    self.tcb.thisside)
        #Different values then 0 and 1 to tcpflags TODO
        #self.assertEqual(ipfin, ipfinreceived)
        #self.assertEqual(tcpfin, tcpfinreceived)
        
    #
    #Receiving ACK from FIN sent
    #

        #THISSIDE
        #Receiving ACK 
        (ipfinack, tcpfinack) = receive(self, self.tcb, self.tcb.thisside, self.tcb.thatside) 
        assertSequenceAcknowledgmentOK(self, self.tcb, tcpfinack, self.tcb.thisside, self.tcb.thatside)

        print tcpfinack 

    #
    #Receiving FIN
    #
        #test if FIN was sent in the same segment
        if (tcpfinack.fin == None or tcpfinack.fin == 0):
            
 	    #TODO same attribute used (ipfinack, tcpfinack)
            (ipfinack, tcpfinack) = receive(self, self.tcb, self.tcb.thisside,\
							      self.tcb.thatside)
            assertSequenceAcknowledgmentOK(self, self.tcb, tcpfinack, \
					self.tcb.thisside, self.tcb.thatside)
        
        assertFin(self, tcpfinack)

        print tcpfinack 
        
        #Fin consumes a sequence
        self.tcb.tcpsequence[ self.tcb.thatside ] += 1
             
    #
    #Sending ACK
    #

        #THISSIDE
        (ipackfin, tcpackfin) = createip(self, self.tcb, self.tcb.thisside, 
							   self.tcb.thatside)
        createwritepacket(self, self.tcb, ipackfin, tcpackfin, \
				self.tcb.thisside, self.tcb.thatside)
        print tcpackfin 

        #THATHSIDE
        #Receiving SYN (receiving from the same board) 
        (ipackfinreceived, tcpackfinreceived) = receive(self, self.tcb, \
					self.tcb.thatside, self.tcb.thisside) 
                                  
        #Different values then 0 and 1 to tcpflags TODO
        #self.assertEqual(ipackfin, ipackfinreceived)
        #self.assertEqual(tcpackfin, tcpackfinreceived)

        

def assertAcknowledgmentPresent(self, tcp):
    """RFC??
       ...ack must be present in every packet since step #2 of 3wayhand
    """
    self.failIf(tcp.ack < 1)
    self.assertNotEqual(tcp.ack_number, 0)
    self.assertNotEqual(tcp.ack_number, None)

def assertSynPresent(self, tcp):
    """
    """
    self.failIf(tcp.syn < 1)
    assertSequencePresent(self, tcp)

def assertSequencePresent(self, tcp):
    """RFC793-P24-p1
       A fundamental notion in the design is that every octet of data sent
    over a TCP connection has a sequence number.
    """
    self.assertNotEqual(tcp.sequence, 0)
    self.assertNotEqual(tcp.sequence, None)

def assertExpectedSequence(self, tcb, tcp, from_, to):
    """RFC??
    """
    self.assertEqual(tcp.sequence, tcb.tcpsequence[ to ])

def assertExpectedAcknowledgment(self, tcb, tcp, from_, to):
    """RFC793-P16-p2
       Acknowledgment Number, value of the next sequence number the sender of
    the segment is expecting to receive
    """
    self.assertEqual(tcp.ack_number, tcb.tcpsequence[ from_ ])

def assertSequenceAcknowledgmentOK(self, tcb, tcp, from_, to):
    
    #RFC793-P24-p1
    assertSequencePresent(self, tcp)
    #RFC TODO
    assertAcknowledgmentPresent(self, tcp)
    #RFC793-P16-p2
    assertExpectedAcknowledgment(self, tcb, tcp, from_, to)
    #RFC TODO
    assertExpectedSequence(self, tcb, tcp, from_, to)


def assertFin(self, tcp):
    """is fin flag on?
    """
    self.failIf(tcp.fin<1)
    

def createsyn(self, tcb, from_, to):
    """Create tcp syn flag expertise"""

    (ip, tcp) = createip(self, tcb, from_, to)

    #business
    tcp.syn = 1
    tcp.ack = 0
    tcb.tcpsequence[ from_ ] += 1

    return (ip, tcp)

def createfin(self, tcb, from_, to):
    """Create tcp fin flag expertise"""

    (ip, tcp) = createip(self, tcb, from_, to)

    #business
    tcp.fin = 1
    tcb.tcpsequence[ from_ ] += 1

    return (ip, tcp)
          
def createip(self, tcb, from_, to):
    """Create ip packet
    tcp is also created here"""
    ip1 = ipv4.ipv4()

    ip1.version = 4 
    ip1.hlen = 5   
    ip1.tos = 0     
    ip1.id = tcb.ipid[ from_ ] 
    ip1.flags = 0 
    ip1.offset = 0
    ip1.ttl = 64
    ip1.protocol = pcs.IPPROTO_TCP
    ip1.src = tcb.ip[ from_ ]
    ip1.dst = tcb.ip[ to ]
    ip1.length = len(ip1.bytes)

    # tcp here
    tcp1 = createtcp(self, tcb, ip1, from_, to)
    
    ip1.length = len(ip1.bytes) + len(tcp1.bytes) 
    #ip1.checksum = ip_cksum(ip1) #doind this at checkout(createwritepacket)
    
    return (ip1, tcp1) 


def createtcp(self, tcb, ip, from_, to):
    """Create tcp packet"""
    tcp1 = tcp.tcp()

    tcp1.sport = tcb.tcpport[ from_ ] 
    tcp1.dport = tcb.tcpport[ to ]
    tcp1.sequence = tcb.tcpsequence[ from_ ]        
    tcp1.ack_number = tcb.tcpsequence[ to ]
    tcp1.offset = 5
    tcp1.urgent = 0
    tcp1.ack = 1
    tcp1.push = 0
    tcp1.reset = 0
    tcp1.syn = 0
    tcp1.fin = 0
    tcp1.window = (1<<16)-1
    tcp1.urg_point = 0
    #tcp1.options

    #tcp1.checksum = tcp_cksum(tcp1 , ip) #doind this at checkout(createwrite)

    return tcp1


def receive(self, tcb, from_, to):
    """receive packet for this socket
    This method must handle timmers"""
    (ip, tcp) = (None, None)
    while 1: 
        reply = tcb.output[ from_ ].read()
        try: 
            packet = ethernet.ethernet(reply)
            ip = packet.data
            tcp = ip.data
            if (tcb.ip[ from_ ]==ip.dst and \
                tcb.ip[ to ]==ip.src and \
                tcb.tcpport[ from_ ]==tcp.dport and \
                tcb.tcpport[ to ]==tcp.sport): 
                break
        except: 
            print "packet ignored"
            pass
        
    return (ip, tcp)


def createethernet(self, tcb, from_, to):
    """Create ethernet header"""
    ether1 = ethernet.ethernet()
    ether1.src = tcb.ether[ from_ ]
    ether1.dst = tcb.ether[ to ]                
    ether1.type = 0x800
    
    return ether1


def createwritepacket(self, tcb, ip, tcp, from_, to):
    ether = createethernet(self, tcb, from_, to)

    tcp.checksum = tcp_cksum(tcp , ip) 

    ip.length = len(ip.bytes) + len(tcp.bytes) 
    ip.checksum = ip_cksum(ip)
 
    packet = pcs.Chain([ ether, ip, tcp ])
    tcb.output[ from_ ].write(packet.bytes, len(packet.bytes))
  

def tcp_cksum(self, ip, data = ""):  #TODO: add this method to pcs tcp.py
    """return tcpv4 checksum"""
    import struct
    total = 0
    
    tmpip = ipv4.pseudoipv4()
    tmpip.src = ip.src
    tmpip.dst = ip.dst
    tmpip.reserved = 0 
    tmpip.protocol = pcs.IPPROTO_TCP
    tmpip.length = len(self.getbytes()) + len(data)
    pkt = tmpip.getbytes() + self.getbytes() + data
    if len(pkt) % 2 == 1:
        pkt += "\0"
    for i in range(len(pkt)/2):
        total += (struct.unpack("!H", pkt[2*i:2*i+2])[0])
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
    return  ~total & 0xffff
    

def ip_cksum(ip):    #TODO: solve the self problem, may be adding another arg
    """calculate the IPv4 checksum over a packet
    
    returns the calculated checksum
    """
    import struct
    total = 0
    packet = ipv4.ipv4(ip.bytes)
    packet.checksum = 0
    bytes = packet.bytes
    
    if len(bytes) % 2 == 1:
        bytes += "\0"
      
    for i in range(len(bytes)/2):
        total += (struct.unpack("!H", bytes[2*i:2*i+2])[0])
    
    total = (total >> 16) + (total & 0xffff)
    total += total >> 16
 
    return ~total & 0xffff


if __name__ == '__main__':
    unittest.main()


