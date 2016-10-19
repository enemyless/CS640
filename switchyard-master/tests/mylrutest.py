#!/usr/bin/env python

import sys
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from switchyard.lib.testing import *

def mk_pkt(hwsrc, hwdst, ipsrc, ipdst, reply=False):
    ether = Ethernet()
    ether.src = EthAddr(hwsrc)
    ether.dst = EthAddr(hwdst)
    ether.ethertype = EtherType.IP

    ippkt = IPv4()
    ippkt.srcip = IPAddr(ipsrc)
    ippkt.dstip = IPAddr(ipdst)
    ippkt.protocol = IPProtocol.ICMP
    ippkt.ttl = 32

    icmppkt = ICMP()
    if reply:
        icmppkt.icmptype = ICMPType.EchoReply
    else:
        icmppkt.icmptype = ICMPType.EchoRequest

    return ether + ippkt + icmppkt

def switch_tests():
    s = Scenario("switch tests")
    s.add_interface('eth0', '10:00:00:00:00:01')
    s.add_interface('eth1', '10:00:00:00:00:02')
    s.add_interface('eth2', '10:00:00:00:00:03')
    s.add_interface('eth3', '10:00:00:00:00:04')

    # test case 1: a frame with broadcast destination should get sent out
    # all ports except ingress
    testpkt = mk_pkt("30:00:00:00:00:07", "ff:ff:ff:ff:ff:ff", "172.16.42.2", "255.255.255.255")
    s.expect(PacketInputEvent("eth1", testpkt, display=Ethernet), "broadcast dest arrives on eth1")
    s.expect(PacketOutputEvent("eth0", testpkt, "eth2", testpkt,"eth3", testpkt, display=Ethernet), " broadcast dest flood")

    # test case 2: a frame with any unicast address except one assigned to switch
    # interface should be sent out all ports except ingress
    reqpkt = mk_pkt("20:00:00:00:00:01", "30:00:00:00:00:08", '192.168.1.100','172.16.42.2')
    s.expect(PacketInputEvent("eth0", reqpkt, display=Ethernet), "from 20:00:00:00:00:01 to 30:00:00:00:00:02 arrives on eth0")
    s.expect(PacketOutputEvent("eth1", reqpkt, "eth2", reqpkt,"eth3", reqpkt, display=Ethernet), "dest for 30:00:00:00:00:02 flood") 

    # test case 3: a frame with any unicast address except one assigned to switch
    resppkt = mk_pkt("30:00:00:00:00:08", "20:00:00:00:00:01", '172.16.42.2', '192.168.1.100', reply=True)
    s.expect(PacketInputEvent("eth1", resppkt, display=Ethernet), "from 30:00:00:00:00:02 to 20:00:00:00:00:01 arrives on eth1")
    s.expect(PacketOutputEvent("eth0", resppkt, display=Ethernet), "dest 20:00:00:00:00:01 eth0")

    # test case 4: a frame with dest address of one of the interfaces should
    # result in nothing happening
    reqpkt = mk_pkt("30:00:00:00:00:13", "10:00:00:00:00:03", '192.168.1.100','172.16.42.2')
    s.expect(PacketInputEvent("eth2", reqpkt, display=Ethernet), "eth2 with destination address the same as eth2's MAC address")
    s.expect(PacketInputTimeoutEvent(1.0), "drop the packet.")
    
    # test case 5: a frame with broadcast destination should get sent out
    # all ports except ingress
    testpkt = mk_pkt("30:00:00:00:00:09", "ff:ff:ff:ff:ff:ff", "172.16.42.2", "255.255.255.255")
    s.expect(PacketInputEvent("eth0", testpkt, display=Ethernet), "broadcast dest arrives on eth0")
    s.expect(PacketOutputEvent("eth1", testpkt, "eth2", testpkt, "eth3", testpkt , display=Ethernet), "broadcast dest flood")
    
    # test case 6: a frame with dest address of one of the interfaces should
    # result in nothing happening
    reqpkt = mk_pkt("30:00:00:00:00:01", "10:00:00:00:00:01", '192.168.1.100','172.16.42.2')
    s.expect(PacketInputEvent("eth2", reqpkt, display=Ethernet), "An Ethernet frame should arrive on eth2 with destination address the same as eth2's MAC address")
    s.expect(PacketInputTimeoutEvent(1.0), "The switch should not do anything in response to a frame arriving with a destination address referring to the switch itself.")
    
    # test case 7
    testpkt = mk_pkt("30:00:00:00:00:01", "30:00:00:00:00:04", '192.168.1.100','172.16.42.2')
    s.expect(PacketInputEvent("eth1", testpkt, display=Ethernet), "from 30:00:00:00:00:01 to 30:00:00:00:00:04 arrives on eth1")
    s.expect(PacketOutputEvent("eth0", testpkt, "eth2", testpkt, "eth3", testpkt , display=Ethernet), "flood")

    # test case 8
    testpkt = mk_pkt("30:00:00:00:00:02", "30:00:00:00:00:01", '192.168.1.100','172.16.42.2')
    s.expect(PacketInputEvent("eth3", testpkt, display=Ethernet), "from 30:00:00:00:00:02 to 30:00:00:00:00:01 arrives on eth3")
    s.expect(PacketOutputEvent("eth1", testpkt , display=Ethernet), "eth1")

    # test case 9
    testpkt = mk_pkt("30:00:00:00:00:03", "30:00:00:00:00:01", '192.168.1.100','172.16.42.2')
    s.expect(PacketInputEvent("eth2", testpkt, display=Ethernet), "from 30:00:00:00:00:03 to 30:00:00:00:00:01 arrives on eth2")
    s.expect(PacketOutputEvent("eth1", testpkt , display=Ethernet), "eth1")

    # test case 10
    testpkt = mk_pkt("30:00:00:00:00:04", "30:00:00:00:00:01", '192.168.1.100','172.16.42.2')
    s.expect(PacketInputEvent("eth2", testpkt, display=Ethernet), "from 30:00:00:00:00:04 to 30:00:00:00:00:01 arrives on eth2")
    s.expect(PacketOutputEvent("eth1", testpkt , display=Ethernet), "eth1")

    # test case 11
    testpkt = mk_pkt("30:00:00:00:00:05", "30:00:00:00:00:01", '192.168.1.100','172.16.42.2')
    s.expect(PacketInputEvent("eth3", testpkt, display=Ethernet), "from 30:00:00:00:00:05 to 30:00:00:00:00:01 arrives on eth3")
    s.expect(PacketOutputEvent("eth1", testpkt , display=Ethernet), "eth1")

    # test case 12
    testpkt = mk_pkt("30:00:00:00:00:06", "30:00:00:00:00:02", '192.168.1.100','172.16.42.2')
    s.expect(PacketInputEvent("eth0", testpkt, display=Ethernet), "from 30:00:00:00:00:06 to 30:00:00:00:00:02 arrives on eth1")
    s.expect(PacketOutputEvent("eth1", testpkt, "eth2", testpkt, "eth3", testpkt , display=Ethernet), "flood due to LRU kicked h2")

    # test case 13
    testpkt = mk_pkt("30:00:00:00:00:05", "30:00:00:00:00:03", '192.168.1.100','172.16.42.2')
    s.expect(PacketInputEvent("eth0", testpkt, display=Ethernet), "from 30:00:00:00:00:05 to 30:00:00:00:00:03 arrives on eth0")
    s.expect(PacketOutputEvent("eth2", testpkt, display=Ethernet), "eth2")

    # test case 14
    testpkt = mk_pkt("30:00:00:00:00:07", "30:00:00:00:00:04", '192.168.1.100','172.16.42.2')
    s.expect(PacketInputEvent("eth0", testpkt, display=Ethernet), "from 30:00:00:00:00:01 to 30:00:00:00:00:04 arrives on eth0")
    s.expect(PacketOutputEvent("eth1", testpkt, "eth2", testpkt, "eth3", testpkt , display=Ethernet), "flood due to LRU kicked h4")
    return s

scenario = switch_tests()
