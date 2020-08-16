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
# Description: To verify that the device correctly sends reset segments 
#              while in a non sync state 
#              
#

import unittest 
from pcs.packets import ipv4
from pcs.packets import tcp
from pcs.packets import ethernet
import tcptest
import pcs
import pdb, time, random

class TestResetFromNonSyncState(unittest.TestCase):
    """
       RFC 793 - Section 3.4 Establishing a Connection
       Page 36 - Reset Generation  

       2.  If the connection is in any non-synchronized state (LISTEN,
       SYN-SENT, SYN-RECEIVED), and the incoming segment acknowledges
       something not yet sent (the segment carries an unacceptable ACK), or
       if an incoming segment has a security level or compartment which
       does not exactly match the level and compartment requested for the
       connection, a reset is sent.
    
       [PREPARATION]
       ==at DEVICE UNDER TEST(DUT)
         inetd with descard server running (port 9)

    """

    def resetTcb(self, tcb):

        tcb.ip = { self.thisside : pcs.inet_atol("10.211.55.210") , \
                    self.thatside : pcs.inet_atol("10.211.55.220")}
       
       
        tcb.ipid = { self.thisside : random.randrange(1, (1<<16)-1) , \
                      self.thatside : 0}
       
       
        tcb.tcpport = { self.thisside : random.randrange(50000, 60000) , \
                         self.thatside : 9}
       
        tcb.tcpsequence = { self.thisside : random.randrange(1,(1<<32)-1),\
                             self.thatside : 0}
       
         
        tcb.ether = \
                { self.thisside : ethernet.ether_atob("00:1c:42:9d:57:c9") , \
                  self.thatside : ethernet.ether_atob("00:1c:42:db:c5:22") }
    
        
        tcb.output = { self.thisside : pcs.PcapConnector("ed0") , \
                        self.thatside : pcs.PcapConnector("ed0") }


    def setUp(self):
        """
        """
        import random
        
        #constants
        self.thisside = 0
        self.thatside = 1

        self.tcb = tcptest.tcb()
        self.resetTcb(self.tcb)
        
    def testResetFromNonSyncStateListen(self):
        
        """
           RFC 793 - Section 3.4 Establishing a Connection
           Page 36 - Reset Generation  
    
           2.  If the connection is in any non-synchronized state (LISTEN,
           SYN-SENT, SYN-RECEIVED), and the incoming segment acknowledges
           something not yet sent (the segment carries an unacceptable ACK), or
           if an incoming segment has a security level or compartment which
           does not exactly match the level and compartment requested for the
           connection, a reset is sent.

           Sent an ACK without any other previous sent.
        """

        #Create a tcp segment with only ack bit set, and a fake ack_number 
        (ip, tcp) = tcptest.createoutofwindowack(self, self.tcb, self.thisside, self.thatside)
        tcptest.createwritepacket(self, self.tcb, ip, tcp, self.thisside, self.thatside)

        (iprst, tcprst) = tcptest.receive(self, self.tcb, self.thisside, self.thatside) 
        tcptest.assertReset(self, self.tcb, tcprst, self.thisside, self.thatside, tcp)


    def testResetFromNonSyncStateSynReceived(self):
        
        """
           RFC 793 - Section 3.4 Establishing a Connection
           Page 36 - Reset Generation  
    
           2.  If the connection is in any non-synchronized state (LISTEN,
           SYN-SENT, SYN-RECEIVED), and the incoming segment acknowledges
           something not yet sent (the segment carries an unacceptable ACK), or
           if an incoming segment has a security level or compartment which
           does not exactly match the level and compartment requested for the
           connection, a reset is sent.

           Sent an ACK without any other previous sent.
        """

        self.resetTcb( self.tcb )
        
        (ipsyn, tcpsyn) = tcptest.createsyn(self, self.tcb, self.thisside, self.thatside)
        tcptest.createwritepacket(self, self.tcb, ipsyn, tcpsyn, self.thisside, self.thatside)   
        
        (ipsynack, tcpsynack) = tcptest.receive(self, self.tcb, self.thisside, self.thatside)

        #Create a tcp segment with only ack bit set, and a fake ack_number 
        (ip, tcp) = tcptest.createoutofwindowack(self, self.tcb, self.thisside, self.thatside)
        tcptest.createwritepacket(self, self.tcb, ip, tcp, self.thisside, self.thatside)
           
        (iprst, tcprst) = tcptest.receive(self, self.tcb, self.thisside, self.thatside) 
        tcptest.assertReset(self, self.tcb, tcprst, self.thisside, self.thatside, tcp)


if __name__ == '__main__':
    unittest.main()
