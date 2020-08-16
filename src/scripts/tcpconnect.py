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
# Description: A simple test of three way handshake 
#

from pcs.packets import ipv4
from pcs.packets import tcp
from pcs.packets import ethernet
import pcs

def main():

    from optparse import OptionParser

    parser = OptionParser()
    parser.add_option("-i", "--interface",
                      dest="interface", default=None,
                      help="Network interface to send on.")

    parser.add_option("-t", "--target",
                      dest="ip_target", default=None,
                      help="IPv4 target address to lookup.")
    
    parser.add_option("-s", "--ip_source",
                      dest="ip_source", default=None,
                      help="IPv4 source address to use.")
    
    parser.add_option("-d", "--ether_destination",
                      dest="ether_destination", default=None,
                      help="Ethernet destination address to use.")
    
    parser.add_option("-e", "--ether_source",
                      dest="ether_source", default=None,
                      help="Ethernet source address to use.")
    
    parser.add_option("-o", "--source-port",
                      dest="source_port", default=None,
                      help="Tcp source port.")
    
    parser.add_option("-x", "--destination-port",
                      dest="destination_port", default=None,
                      help="Tcp destination port.")
    
    (options, args) = parser.parse_args()

    import random

    ipid = random.randrange(1,(1<<16)-1)
    tcpsport = random.randrange(50000,60000) #int(options.source_port )
    tcpsequence = random.randrange(1,(1<<32)-1)   
    output = pcs.PcapConnector(options.interface)

    replyip = None
    replytcp = None 
    reply = None 
    packet = None

 # SYN
    what = "SYN"

    ip1 = ipv4.ipv4()

    ip1.version = 4 
    ip1.hlen = 5   
    ip1.tos = 0     
    ip1.id = ++ipid 
    ip1.flags = 0 
    ip1.offset = 0
    ip1.ttl = 64
    ip1.protocol = pcs.IPPROTO_TCP
    ip1.src = pcs.inet_atol(options.ip_source)
    ip1.dst = pcs.inet_atol(options.ip_target)
    
    tcp1 = tcp.tcp()

    tcp1.sport = tcpsport 
    tcp1.dport = int(options.destination_port)
    tcp1.sequence = tcpsequence
    tcpsequence = tcpsequence + 1  # SYN consumes the sequence
    tcp1.ack_number = 0
    tcp1.offset = 5
    tcp1.urgent = 0
    tcp1.ack = 0
    tcp1.push = 0
    tcp1.reset = 0
    tcp1.syn = 1
    tcp1.fin = 0
    tcp1.window = (1<<16)-1
    tcp1.urg_point = 0
    #tcp1.options

    tcp1.checksum = tcp_cksum(tcp1 , ip1)

    ip1.length = len(ip1.bytes) + len(tcp1.bytes) 

    # important, only calcs the ip checksum after fill length field
    ip1.checksum = ip_cksum(ip1)

    ether1 = ethernet.ethernet()
    ether1.src = ethernet.ether_atob(options.ether_source)
    ether1.dst = ethernet.ether_atob(options.ether_destination)
    ether1.type = 0x800

    packet = pcs.Chain([ether1, ip1, tcp1])
    
    print "\n%s---------------------------------" % what
    print tcp1 
    print "---------------------------------"

    out = output.write(packet.bytes, len(packet.bytes))

## SYN
 # SYN+ACK
    what = "SYN+ACK"

    while 1: 
    	reply = output.read()
    	packet = ethernet.ethernet(reply)
   	try: 
    		replyip = packet.data
    		replytcp = replyip.data
		if (ip1.src==replyip.dst and \
			ip1.dst==replyip.src and \
			tcp1.sport==replytcp.dport and \
			tcp1.dport==replytcp.sport): 
			break
	except: #it cannot be a tcp packet (without sport:)
		pass

    print "\n%s---------------------------------" % what
    print packet.data.data
    print "---------------------------------"

## SYN+ACK
 # ACK 134,187
    what = "ACK (SYN)"

    ip3 = ipv4.ipv4()

    ip3.version = 4 
    ip3.hlen = 5   
    ip3.tos = 0     
    ip3.id = ++ipid
    ip3.flags = 0 
    ip3.offset = 0
    ip3.ttl = 64
    ip3.protocol = pcs.IPPROTO_TCP
    ip3.src = pcs.inet_atol(options.ip_source)
    ip3.dst = pcs.inet_atol(options.ip_target)
    
    tcp3 = tcp.tcp()

    tcp3.sport = tcpsport 
    tcp3.dport = int(options.destination_port)
    tcp3.sequence = tcpsequence
    ##tcpsequence = tcpsequence + 1  # ACK DOES NOT consumes the sequence
    tcp3.ack_number = replytcp.sequence + 1 
    tcp3.offset = 5
    tcp3.urgent = 0
    tcp3.ack = 1
    tcp3.push = 0
    tcp3.reset = 0
    tcp3.syn = 0
    tcp3.fin = 0
    tcp3.window = (1<<16)-1
    tcp3.urg_point = 0
    #tcp3.options

    tcp3.checksum = tcp_cksum(tcp3 , ip3)

    ip3.length = len(ip3.bytes) + len(tcp3.bytes) 

    # important, only calcs the ip checksum after fill length field
    ip3.checksum = ip_cksum(ip3)

    ether3 = ethernet.ethernet()
    ether3.src = ethernet.ether_atob(options.ether_source)
    ether3.dst = ethernet.ether_atob(options.ether_destination)
    ether3.type = 0x800

    packet = pcs.Chain([ether3, ip3, tcp3])
    
    print "\n%s---------------------------------" % what
    print tcp3 
    print "---------------------------------"

    out = output.write(packet.bytes, len(packet.bytes))

## ACK
 # FIN 188,241 
    what = "FIN"

    ip4 = ipv4.ipv4()

    ip4.version = 4 
    ip4.hlen = 5   
    ip4.tos = 0     
    ip4.id = ++ipid
    ip4.flags = 0 
    ip4.offset = 0
    ip4.ttl = 64
    ip4.protocol = pcs.IPPROTO_TCP
    ip4.src = pcs.inet_atol(options.ip_source)
    ip4.dst = pcs.inet_atol(options.ip_target)
    
    tcp4 = tcp.tcp()

    tcp4.sport = tcpsport 
    tcp4.dport = int(options.destination_port)
    tcp4.sequence = tcpsequence
    tcpsequence = tcpsequence + 1  # FIN consumes the sequence
    tcp4.ack_number = replytcp.sequence + 1 
    tcp4.offset = 5
    tcp4.urgent = 0
    tcp4.ack = 1
    tcp4.push = 0
    tcp4.reset = 0
    tcp4.syn = 0
    tcp4.fin = 1
    tcp4.window = (1<<16)-1
    tcp4.urg_point = 0
    #tcp4.options

    tcp4.checksum = tcp_cksum(tcp4 , ip4)

    ip4.length = len(ip4.bytes) + len(tcp4.bytes) 

    # important, only calcs the ip checksum after fill length field
    ip4.checksum = ip_cksum(ip4)

    ether4 = ethernet.ethernet()
    ether4.src = ethernet.ether_atob(options.ether_source)
    ether4.dst = ethernet.ether_atob(options.ether_destination)
    ether4.type = 0x800

    packet = pcs.Chain([ether4, ip4, tcp4])
    
    print "\n%s---------------------------------" % what
    print tcp4 
    print "---------------------------------"

    out = output.write(packet.bytes, len(packet.bytes))

## FIN
 # ACK (FIN) 
    what = "ACK (FIN)"

    while 1: 
    	reply = output.read()
    	packet = ethernet.ethernet(reply)
   	try: 
    		replyip = packet.data
    		replytcp = replyip.data
		if (ip1.src==replyip.dst and \
			ip1.dst==replyip.src and \
			tcp1.sport==replytcp.dport and \
			tcp1.dport==replytcp.sport): 
			break
	except: #it cannot be a tcp packet (without sport:)
		pass

    print "\n%s---------------------------------" % what
    print packet.data.data
    print "---------------------------------"

## ACK (FIN)
 # FIN 
    what = "FIN"

    while 1: 
    	reply = output.read()
    	packet = ethernet.ethernet(reply)
   	try: 
    		replyip = packet.data
    		replytcp = replyip.data
		if (ip1.src==replyip.dst and \
			ip1.dst==replyip.src and \
			tcp1.sport==replytcp.dport and \
			tcp1.dport==replytcp.sport): 
			break
	except: #it cannot be a tcp packet (without sport:)
		pass

    print "\n%s---------------------------------" % what
    print packet.data.data
    print "---------------------------------"

## FIN
 # ACK (FIN) 288,341
    what = "ACK (FIN)"

    ip7 = ipv4.ipv4()

    ip7.version = 4 
    ip7.hlen = 5   
    ip7.tos = 0     
    ip7.id = ++ipid
    ip7.flags = 0 
    ip7.offset = 0
    ip7.ttl = 64
    ip7.protocol = pcs.IPPROTO_TCP
    ip7.src = pcs.inet_atol(options.ip_source)
    ip7.dst = pcs.inet_atol(options.ip_target)
    
    tcp7 = tcp.tcp()

    tcp7.sport = tcpsport 
    tcp7.dport = int(options.destination_port)
    tcp7.sequence = tcpsequence
    ##tcpsequence = tcpsequence + 1  # ACK DOES NOT consumes the sequence
    tcp7.ack_number = replytcp.sequence + 1 
    tcp7.offset = 5
    tcp7.urgent = 0
    tcp7.ack = 1
    tcp7.push = 0
    tcp7.reset = 0
    tcp7.syn = 0
    tcp7.fin = 0
    tcp7.window = (1<<16)-1
    tcp7.urg_point = 0
    #tcp7.options

    tcp7.checksum = tcp_cksum(tcp7 , ip7)

    ip7.length = len(ip7.bytes) + len(tcp7.bytes) 

    # important, only calcs the ip checksum after fill length field
    ip7.checksum = ip_cksum(ip7)

    ether7 = ethernet.ethernet()
    ether7.src = ethernet.ether_atob(options.ether_source)
    ether7.dst = ethernet.ether_atob(options.ether_destination)
    ether7.type = 0x800

    packet = pcs.Chain([ether7, ip7, tcp7])
    
    print "\n%s---------------------------------" % what
    print tcp7 
    print "---------------------------------"

    out = output.write(packet.bytes, len(packet.bytes))

## ACK (FIN)

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

def ip_cksum(self):    #TODO: solve the self problem, may be adding another arg
    """calculate the IPv4 checksum over a packet

    returns the calculated checksum
    """
    import struct
    total = 0
    packet = ipv4.ipv4(self.bytes)
    packet.checksum = 0
    bytes = packet.bytes

    if len(bytes) % 2 == 1:
        bytes += "\0"

    for i in range(len(bytes)/2):
        total += (struct.unpack("!H", bytes[2*i:2*i+2])[0])

    total = (total >> 16) + (total & 0xffff)
    total += total >> 16

    return ~total & 0xffff


main()
