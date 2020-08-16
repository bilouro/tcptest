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
#              while in a closed state 
#              
#

import unittest 
from pcs.packets import ipv4
from pcs.packets import tcp
from pcs.packets import ethernet
import tcptest
import pcs
import pdb
import time

class TestResetFromClosedState(unittest.TestCase):
    """
       RFC 793 - Section 3.4 Establishing a Connection
       Page 36 - Reset Generation  

       As a general rule, reset (RST) must be sent whenever a segment arrives
       which apparently is not intended for the current connection.  A reset
       must not be sent if it is not clear that this is the case.

       [PREPARATION]
       ==at DEVICE UNDER TEST(DUT)
         inetd with descard server running (port 9)
         you must have access DUT's shell with kill -TERM inetd process and /etc/rc.d/inetd stop privileges 

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
        
    def testResetFromClosedStateSYNwithACK(self):
        """
        RFC 793 - Section 3.4 Establishing a Connection
        Page 36

        1.  If the connection does not exist (CLOSED) then a reset is sent
        in response to any incoming segment except another reset.  In
        particular, SYNs addressed to a non-existent connection are rejected
        by this means.

        If the incoming segment has an ACK field, the reset takes its
        sequence number from the ACK field of the segment, otherwise the
        reset has sequence number zero and the ACK field is set to the sum
        of the sequence number and segment length of the incoming segment.
        The connection remains in the CLOSED state.
        
        Procedure:
        (1)establish a connection
        (2)the DUT make a active close
        (3)we wait for a couple of MSL (enough time to connection go to closed-state)
        (4)send a SYN with ACK of the above connection
        (5)waits for a RESET with sequence equals to ack sent 
        """

        #(1)establish a connection
        tcptest.threewayhandshakenoopt(self, self.tcb, self.thisside, self.thatside)   

        #(2)the DUT make a active close
        print "################"
        print "# IMPORTANT NOTE"
        print "################"
        print "#"
        print "# At this moment you shoud do the following in the device under test(DUT):"
        print '# > socket -4 | grep "\:9"'
        print "# > kill -TERM <PID_OF_INETD>"
        print "# > /etc/rc.d/inetd stop"
        print "# "
        tcptest.passivecloseconnection(self, self.tcb, self.thisside, self.thatside) 

        #(3)we wait for a couple of MSL (enough time to connection go to closed-state)
        print "# "
        print "# Waiting for a couple of MSL(Maximun Segment Lifetime)"
        time.sleep(60) #2MSL(freebsd7)

        #(4)send a SYN with ACK of the above connection
        # 
        #--->Sending SYN
        (ipsyn, tcpsyn) = tcptest.createsyn(self, self.tcb, self.thisside, self.thatside)   
        #createsyn sets ack bit to 0 
        tcpsyn.ack = 1
        tcptest.createwritepacket(self, self.tcb, ipsyn, tcpsyn, self.thisside, self.thatside)   

        #(5)waits for a RESET with sequence equals to ack sent
        (ipfinack, tcpfinack) = tcptest.receive(self,self.tcb, self.thisside, self.thatside) 
        tcptest.assertReset(self, self.tcb, tcpfinack, self.thisside, self.thatside, tcpsyn)

    
    def testResetFromNonExistentConnectionSYN(self):
        """
        RFC 793 - Section 3.4 Establishing a Connection
        Page 36

        1.  If the connection does not exist (CLOSED) then a reset is sent
        in response to any incoming segment except another reset.  In
        particular, SYNs addressed to a non-existent connection are rejected
        by this means.

        If the incoming segment has an ACK field, the reset takes its
        sequence number from the ACK field of the segment, otherwise the
        reset has sequence number zero and the ACK field is set to the sum 
        of the sequence number and segment length of the incoming segment.
        The connection remains in the CLOSED state.

        Procedure:
        (1)reset our tcb sequence and sport records.
        (2)send a SYN withOUT ACK(ack bit=0, ack_number=0) 
        (3)waits for a RESET with sequence equals to zero and ACK field is set to the sum
        of the sequence number and segment length of the incoming segment
        """
        self.tcb.tcpport = { self.thisside : random.randrange(50000, 60000) , \
            self.thatside : 9}
        self.tcb.tcpsequence = { self.thisside : random.randrange(1,(1<<32)-1),\
            self.thatside : 0}

        (ipsyn, tcpsyn) = tcptest.createsyn(self, self.tcb, self.thisside, self.thatside)   
        tcptest.createwritepacket(self, self.tcb, ipsyn, tcpsyn, self.thisside, self.thatside)   
        (ipfinack, tcpfinack) = tcptest.receive(self,self.tcb, self.thisside, self.thatside) 
        tcptest.assertReset(self, self.tcb, tcpfinack, self.thisside, self.thatside, tcpsyn)


    def testResetFromNonExistentConnectionFIN(self):
        """
        RFC 793 - Section 3.4 Establishing a Connection
        Page 36

        1.  If the connection does not exist (CLOSED) then a reset is sent
        in response to any incoming segment except another reset.  In
        particular, SYNs addressed to a non-existent connection are rejected
        by this means.

        If the incoming segment has an ACK field, the reset takes its
        sequence number from the ACK field of the segment, otherwise the
        reset has sequence number zero and the ACK field is set to the sum 
        of the sequence number and segment length of the incoming segment.
        The connection remains in the CLOSED state.

        Procedure:
        (1)reset our tcb sequence and sport records.
        (2)send a ACK withOUT ACK(ack bit=0, ack_number=0) 
        (3)waits for a RESET with sequence equals to zero and ACK field is set to the sum
        of the sequence number and segment length of the incoming segment
        """
        self.tcb.tcpport = { self.thisside : random.randrange(50000, 60000) , \
            self.thatside : 9}
        self.tcb.tcpsequence = { self.thisside : random.randrange(1,(1<<32)-1),\
            self.thatside : 0}

        (ipfin, tcpfin) = tcptest.createfin(self, self.tcb, self.thisside, self.thatside)   
        tcptest.createwritepacket(self, self.tcb, ipfin, tcpfin, self.thisside, self.thatside)   
        (ipfinack, tcpfinack) = tcptest.receive(self,self.tcb, self.thisside, self.thatside) 
        tcptest.assertReset(self, self.tcb, tcpfinack, self.thisside, self.thatside, tcpfin)


    def testResetFromNonExistentConnectionRST(self):
        """
        RFC 793 - Section 3.4 Establishing a Connection
        Page 36

        1.  If the connection does not exist (CLOSED) then a reset is sent
        in response to any incoming segment except another reset.  In
        particular, SYNs addressed to a non-existent connection are rejected
        by this means.

        If the incoming segment has an ACK field, the reset takes its
        sequence number from the ACK field of the segment, otherwise the
        reset has sequence number zero and the ACK field is set to the sum 
        of the sequence number and segment length of the incoming segment.
        The connection remains in the CLOSED state.

        Procedure:
        (1)reset our tcb sequence and sport records.
        (2)send a ACK withOUT ACK(ack bit=0, ack_number=0) 
        (3)waits for a RESET with sequence equals to zero and ACK field is set to the sum
        of the sequence number and segment length of the incoming segment
        """
        self.tcb.tcpport = { self.thisside : random.randrange(50000, 60000) , \
            self.thatside : 9}
        self.tcb.tcpsequence = { self.thisside : random.randrange(1,(1<<32)-1),\
            self.thatside : 0}

        (ipsyn, tcpsyn) = tcptest.createfakerstfromtcb(self, self.tcb, self.thisside, self.thatside)   
        tcptest.createwritepacket(self, self.tcb, ipsyn, tcpsyn, self.thisside, self.thatside)
        
        #TODO:We need wait 2MSL to be sure the receiver didn't answer 
        #TODO:We need a socket method to listen for up to certain seconds.
        (ipfinack, tcpfinack) = tcptest.receive(self,self.tcb, self.thisside, self.thatside) 


if __name__ == '__main__':
    unittest.main()
