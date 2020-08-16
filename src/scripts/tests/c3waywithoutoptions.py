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
# Description: Sends an syn to broadcast address, the destination host 
#              cannot answer this send 
#

import unittest 
from pcs.packets import ipv4
from pcs.packets import tcp
from pcs.packets import ethernet
import tcptest
import pcs
import pdb

class TestSendSyn4BroadcastAddress(unittest.TestCase):
    """
       Sends an syn to broadcast address, the destination host 
       cannot answer this send 
    """

    def setUp(self):
        """
        """
        import random
        
        #constants
        self.thisside = 0
        self.thatside = 1

        self.tcb = tcptest.tcb()
        
        self.tcb.ip = { self.thisside : pcs.inet_atol("10.211.55.210") , \
                    self.thatside : pcs.inet_atol("10.211.55.220")}
	

        self.tcb.ipid = { self.thisside : random.randrange(1, (1<<16)-1) , \
                      self.thatside : 0}


        self.tcb.tcpport = { self.thisside : random.randrange(50000, 60000) , \
                         self.thatside : 9}

        self.tcb.tcpsequence = { self.thisside : random.randrange(1,(1<<32)-1),\
                             self.thatside : 0}
        
	
        self.tcb.ether = \
                { self.thisside : ethernet.ether_atob("00:1c:42:9d:57:c9") , \
                  self.thatside : ethernet.ether_atob("00:1c:42:db:c5:22") }


        self.tcb.output = { self.thisside : pcs.PcapConnector("ed0") , \
                        self.thatside : pcs.PcapConnector("ed0") } 
        
        
        

    def testSendSyn4BroadcastAddress(self):
        #THISSIDE
        (ipsyn, tcpsyn) = tcptest.createsyn(self, self.tcb, self.thisside, self.thatside)
                              
        tcptest.createwritepacket(self, self.tcb, ipsyn, tcpsyn, self.thisside, self.thatside)
                                                           
        
        
        #THATHSIDE
        #Receiving SYN (unfurtunately this time we are receiving from 
        #the same board)
        (ipsynreceived, tcpsynreceived) = tcptest.receive(self, self.tcb, self.thatside, self.thisside)
                                                                    

        self.assertEqual(ipsyn, ipsynreceived)
        self.assertEqual(tcpsyn, tcpsynreceived)
        print ipsynreceived 
        print tcpsynreceived 


    #
    #Receiving SYN+ACK
    #
        #THISSIDE
        #Receivinig SYN + ACK
        (ipsynack, tcpsynack) = tcptest.receive(self, self.tcb, self.thisside, self.thatside) 
                               

    	#Some blackmagic to use assertSequenceAcknowledgmentOK at SYN
        self.tcb.tcpsequence[ self.thatside ] = tcpsynack.sequence  
        tcptest.assertSequenceAcknowledgmentOK(self, self.tcb, tcpsynack, \
                    self.thisside, self.thatside)

        tcptest.assertSynPresent(self, tcpsynack)

        #OK Its a SYN+ACK --> SYN consumes a sequence
        self.tcb.tcpsequence[ self.thatside ] = tcpsynack.sequence + 1
        print tcpsynack 


    #
    #Sending ACK
    #
        #THISSIDE
        (ipack, tcpack) = tcptest.createip(self, self.tcb, self.thisside, \
                             self.thatside)

        tcptest.createwritepacket(self, self.tcb, ipack, tcpack, self.thisside, \
                                                           self.thatside)
        print tcpack 

        #THATHSIDE
        #Receiving SYN (unfurtunately this time we are receiving from the same board) 
	(ipackreceived, tcpackreceived) = tcptest.receive(self, self.tcb, self.thatside, self.thisside)
                                                                    
        #Different values then 0 and 1 to tcpflags TODO
        #self.assertEqual(ipack, ipackreceived)
        #self.assertEqual(tcpack, tcpackreceived)


    #
    #Sending FIN
    #
        #THISSIDE
        (ipfin, tcpfin) = tcptest.createfin(self, self.tcb, self.thisside, self.thatside)
        tcptest.createwritepacket(self, self.tcb, ipfin, tcpfin, self.thisside, \
                                                           self.thatside)
        print tcpfin 

        #THATHSIDE
        #Receiving SYN (unfurtunately this time we are receiving from the same board) 
        (ipfinreceived, tcpfinreceived) = tcptest.receive(self, self.tcb, self.thatside, \
                                                                    self.thisside)
        #Different values then 0 and 1 to tcpflags TODO
        #self.assertEqual(ipfin, ipfinreceived)
        #self.assertEqual(tcpfin, tcpfinreceived)
        
    #
    #Receiving ACK from FIN sent
    #
 #	pdb.set_trace()       

        #THISSIDE
        #Receiving ACK 
        (ipfinack, tcpfinack) = tcptest.receive(self, self.tcb, self.thisside, self.thatside) 
        tcptest.assertSequenceAcknowledgmentOK(self, self.tcb, tcpfinack, self.thisside, self.thatside)

        print tcpfinack 

    #
    #Receiving FIN
    #
        #test if FIN was sent in the same segment
        if (tcpfinack.fin == None or tcpfinack.fin == 0):
            
         #TODO same attribute used (ipfinack, tcpfinack)
            (ipfinack, tcpfinack) = tcptest.receive(self, self.tcb, self.thisside, self.thatside)
                                  
            tcptest.assertSequenceAcknowledgmentOK(self, self.tcb, tcpfinack, \
                    self.thisside, self.thatside)
        
        tcptest.assertFin(self, tcpfinack)

        print tcpfinack 
        
        #Fin consumes a sequence
        self.tcb.tcpsequence[ self.thatside ] += 1
             
    #
    #Sending ACK
    #

        #THISSIDE
        (ipackfin, tcpackfin) = tcptest.createip(self, self.tcb, self.thisside,
                               self.thatside)
        tcptest.createwritepacket(self, self.tcb, ipackfin, tcpackfin, \
                self.thisside, self.thatside)
        print tcpackfin 

        #THATHSIDE
        #Receiving SYN (receiving from the same board) 
        (ipackfinreceived, tcpackfinreceived) = tcptest.receive(self, self.tcb, \
                    self.thatside, self.thisside) 
                                  
        #Different values then 0 and 1 to tcpflags TODO
        #self.assertEqual(ipackfin, ipackfinreceived)
        #self.assertEqual(tcpackfin, tcpackfinreceived)

if __name__ == '__main__':
    unittest.main()

        
        
