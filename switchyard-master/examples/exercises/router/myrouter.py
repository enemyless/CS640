#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
import copy
from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.common import *
import operator

class mappingTableElement(object):
    def __init__(self,ip=None,mac=None,dev=None):
        self.ip = ip
        self.mac = mac
        self.dev = dev 

    def display(self):
        print ("ip=%s,mac=%s,dev=%s\n" % (self.ip,self.mac,self.dev))

class forwardingTableElement(object):
    def __init__(self,prefix=None,netmask=None,nxtHopIP=None,dev=None,prefixlen=None):
        self.prefix = prefix
        self.netmask = netmask
        self.nxtHopIP = nxtHopIP
        self.dev = dev
        self.prefixlen = prefixlen

    def display(self):
        print ("prefix=%s,netmask=%s,nxtHopIP=%s,dev=%s,prefixlen=%s\n" % (self.prefix,self.netmask,self.nxtHopIP,self.dev,self.prefixlen))

class waitQueueElement(object):
    def __init__(self,ethPkt=None,arpPkt=None,dev=None,time=0,retry=0,srcDev=None):
        self.ethPktList = [ethPkt]
        self.arpPkt = arpPkt
        self.dev = dev
        self.time = time
        self.retry = retry
        self.srcDevList= [srcDev]
    
    def display(self):
        for e in self.ethPktList:
            print (e)
        for e in self.srcDevList:
            print (e)
        print (self.arpPkt,"dev=%s,time=%s,retry=%d" % (self.dev,self.time,self.retry))


class Router(object):
    def __init__(self, net):
        self.net = net
        # other initialization stuff here


    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        mappingTable = []
        forwardingTableRouter = []
        forwardingTable = []
        waitQueue = []

        file = os.path.join(os.path.dirname(__file__),"forwarding_table.txt")
        fp = open(file,'r+')

        my_interfaces = self.net.interfaces()
        for intf in my_interfaces:
            print(intf)
            mappingTable.insert(0,mappingTableElement(intf.ipaddr,intf.ethaddr,intf.name))
            intf_network = str(IPv4Network(int(intf.ipaddr)&int(intf.netmask)))
            intf_net = intf_network.split('/')
            intf_prefix=IPv4Network(str(intf_net[0])+'/'+str(intf.netmask))
            intf_prefixlen = intf_prefix.prefixlen
            
            forwardingTable.insert(0,forwardingTableElement(intf_net[0],intf.netmask,None,intf.name,intf_prefixlen))
        #    mappingTable[0].display()

        for line in fp:
            line = line.rstrip()
            item = line.split(" ")
            netaddr = IPv4Network(item[0]+'/'+item[1])
            forwardingTable.insert(0,forwardingTableElement(item[0],item[1],item[2],item[3],netaddr.prefixlen))
            #forwardingTable[0].display()

        forwardingTable.sort(key=operator.attrgetter('prefixlen'),reverse=True)

        for f in forwardingTable:
            f.display()
        for f in forwardingTableRouter:
            f.display()

        
        while True:
            gotpkt = True
            try:
                dev,pkt = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False
            except Shutdown:
                log_debug("Got shutdown signal")
                break

            if gotpkt:
                log_debug("\n\n\nGot a packet-------------------------------------:\n {}".format(str(pkt)))

                # ARP packet
                arp_header = pkt.get_header(Arp)
                
                if arp_header is not None:
                    log_debug("{}".format(str(arp_header)))

                    # ARP request
                    if arp_header.operation == ArpOperation.Request:
                        log_debug("got arp request")                
                        update=0
                        for item in mappingTable:
                            item.display()
                            if item.ip == arp_header.senderprotoaddr:
                                item.mac = arp_header.senderhwaddr
                            #    print ("update")
                                update = 1
                                break
                        if update == 0:
                            mappingTable.insert(0,mappingTableElement(arp_header.senderprotoaddr,arp_header.senderhwaddr,dev))
                        for intf in my_interfaces:
                            if intf.ipaddr == arp_header.targetprotoaddr:
                                arp_reply = create_ip_arp_reply(intf.ethaddr,arp_header.senderhwaddr,arp_header.targetprotoaddr,arp_header.senderprotoaddr)
                                #print (arp_reply)
                                self.net.send_packet(dev,arp_reply)
                                break
                   
                    # ARP reply
                    elif arp_header.operation == ArpOperation.Reply:
                        log_debug("got arp reply")                
                        mappingTable.insert(0,mappingTableElement(arp_header.senderprotoaddr,arp_header.senderhwaddr,dev))
                        for w in waitQueue:
                            w.display()
                            w_arp_header = w.arpPkt.get_header(Arp)
                            if w_arp_header.targetprotoaddr == arp_header.senderprotoaddr:
                                print("match")
                                for p in w.ethPktList:
                                    p[p.get_header_index(Ethernet)].dst = arp_header.senderhwaddr
                                    w.display()
                                    log_debug("send packet on {}".format(str(w.dev)))
                                    self.net.send_packet(w.dev,p) 
                                del waitQueue[waitQueue.index(w)]
                                break
                
                # ipv4 packet (maybe ICMP or other types)
                ipv4_header = pkt.get_header(IPv4)
                icmp_header = pkt.get_header(ICMP)

                if ipv4_header is not None:
                    pktSend = None
                    sendPort = None
                    log_debug("{}".format(str(ipv4_header)))
                    # for the router itself
                    dstRouter = 0;
                    forwardResult = None
                    mappingResult = None

                    icmpErr = 0
                    
                    # if ICMP request for router interface then send back ICMP reply, else drop
                    for intf in my_interfaces:
                        if intf.ipaddr == ipv4_header.dst:
                            if icmp_header is not None:
                                log_debug("Got a ICMP Header {}".format(str(icmp_header)))
                                if icmp_header.icmptype != ICMPType.EchoRequest:
                                    ip = IPv4()
                                    for intf in my_interfaces:
                                        if intf.name == dev:
                                            ip.src = intf.ipaddr
                                    ip.dst = ipv4_header.src
                                    ip.ttl = 64
                                    ip.protocol = IPProtocol.ICMP
                                    icmp = ICMP()
                                    icmp.icmptype = ICMPType.ICMPDestinationUnreachable
                                    icmp.icmpcode = DestinationUnreachable.PortUnreachable
                                    icmpErrPkt = ip + icmp
                                    log_debug("send packet on {}".format(str(dev)))
                                    self.net.send_packet(dev,icmpErrPkt)

                                    icmpErr = 1

                                else:
                                    ip = IPv4()
                                    ip.protocol = IPProtocol.ICMP
                                    ip.src = ipv4_header.dst
                                    ip.dst = ipv4_header.src
                                    ip.ttl = 64
                                    eth = Ethernet()
                                    eth.ethertype = EtherType.IPv4
                                    eth.src = "ff:ff:ff:ff:ff:ff"
                                    eth.dst = "ff:ff:ff:ff:ff:ff"
                                    icmp = ICMP()
                                    icmp.icmptype = ICMPType.EchoReply
                                    icmp.icmpdata.data = icmp_header.icmpdata.data
                                    icmp.icmpdata.identifier = icmp_header.icmpdata.identifier
                                    icmp.icmpdata.sequence = icmp_header.icmpdata.sequence
                                    pktSend = eth + ip + icmp
                            #dstRouter = 1
                            break

                    #if dstRouter != 1:
                    if icmpErr == 0 :# not ICMP for router interface, should be packet to redirect
                        if pktSend is None:# not ICMP for router interface, should be packet to redirect
                            # Construct header
                            #pktSend = copy.copy(pkt)
                            pktSend = pkt
                            print ("aaa")
                            print (pktSend[pktSend.get_header_index(IPv4)].ttl)
                            print ("vvv")
                            pktSend[pktSend.get_header_index(IPv4)].ttl -= 1
                            pktSend[pktSend.get_header_index(Ethernet)].src = "ff:ff:ff:ff:ff:ff"
                            pktSend[pktSend.get_header_index(Ethernet)].dst = "ff:ff:ff:ff:ff:ff"
                        
                        # longest path comparison
                        for f in forwardingTable:
                            prefixnet = IPv4Network(str(f.prefix) + '/' + str(f.prefixlen))
                            match = pktSend[pktSend.get_header_index(IPv4)].dst in prefixnet
                            if match:
                                forwardResult = f
                                break
                        
                        if forwardResult is None:
                            ip = IPv4()
                            ip.ttl = 64
                            for intf in my_interfaces:
                                if intf.name == dev:
                                    ip.src = intf.ipaddr
                            ip.dst = ipv4_header.src
                            ip.protocol = IPProtocol.ICMP
                            icmp = ICMP()
                            icmp.icmptype = ICMPType.ICMPDestinationUnreachable
                            icmp.icmpcode = DestinationUnreachable.NetworkUnreachable
                            icmpErrPkt = ip + icmp
                            log_debug("send packet on {}".format(str(dev)))
                            self.net.send_packet(dev,icmpErrPkt)
                            
                            icmpErr = 1

                        elif pktSend[pktSend.get_header_index(IPv4)].ttl == 0:
                            ip = IPv4()
                            ip.ttl = 64
                            for intf in my_interfaces:
                                if intf.name == dev:
                                    ip.src = intf.ipaddr
                            ip.dst = ipv4_header.src
                            ip.protocol = IPProtocol.ICMP
                            icmp = ICMP()
                            icmp.icmptype = ICMPType.TimeExceeded
                            icmp.icmpcode = ICMPCodeyTimeExceeded.TTLExpired
                            icmpErrPkt = ip + icmp
                            log_debug("send packet on {}".format(str(dev)))
                            self.net.send_packet(dev,icmpErrPkt)
                            icmpErr = 1

                        else: #found forwarding result
                            log_debug("forward result:{}".format(str(forwardResult)))
                            forwardResult.display()
                            for intf in my_interfaces:
                                if intf.name == forwardResult.dev:
                                    pktSend[pktSend.get_header_index(Ethernet)].src = intf.ethaddr
                                    break
                            log_debug("pkt:{}".format(str(pktSend)))

                            
                            # mapping table lookup
                            for m in mappingTable:
                                m.display()
                                forwardResult.display()
                                #forward or network connected directly to the interface
                                if forwardResult.nxtHopIP is None:
                                    if m.ip ==  pktSend[pktSend.get_header_index(IPv4)].dst:
                                        mappingResult = m
                                        break
                                else:
                                    if str(m.ip) == forwardResult.nxtHopIP:
                                        mappingResult = m
                                        break
                        
                            log_debug("mapping result:{}".format(str(mappingResult)))

                            if mappingResult is not None:
                                mappingResult.display()
                                # send
                                #for intf in my_interfaces:
                                pktSend[pktSend.get_header_index(Ethernet)].dst = mappingResult.mac
                                log_debug("send packet on {}".format(str(m.dev)))
                                self.net.send_packet(m.dev,pktSend)

                            else: # no mapping reselt, send ARP request
                                for intf in my_interfaces:
                                    if intf.name == forwardResult.dev:
                                        if forwardResult.nxtHopIP is None: # network connected to router interface
                                            arp_request = create_ip_arp_request( \
                                                    pktSend[pktSend.get_header_index(Ethernet)].src, \
                                                    intf.ipaddr, \
                                                    pktSend[pktSend.get_header_index(IPv4)].dst)
                                        else:
                                            arp_request = create_ip_arp_request( \
                                                    pktSend[pktSend.get_header_index(Ethernet)].src, \
                                                    intf.ipaddr, \
                                                    forwardResult.nxtHopIP)
                                        
                                        log_debug("{}".format(str(arp_request)))

                                        # Share the same arp request for the same dst IP
                                        insertFlg = 1
                                        for w in waitQueue:
                                            w_arp_header = w.arpPkt.get_header(Arp)
                                            arp_request_header = arp_request.get_header(Arp)
                                            if w_arp_header.targetprotoaddr == arp_request_header.targetprotoaddr:
                                                w.ethPktList.append(pktSend)
                                                insertFlg = 0
                                                break
                                        if insertFlg == 1:
                                            waitQueue.insert(0,waitQueueElement(pktSend,arp_request,forwardResult.dev,time.time(),0,dev))
                                            log_debug("send packet on {}".format(str(forwardResult.dev)))
                                            self.net.send_packet(forwardResult.dev,arp_request)
                                        break


                #ICMP
                #icmp_header = xxxxx

            # Check Queue
            # periodically check queue.
            # 1. if found mapping item in mappin g table, then send
            # 2. check ARP status -- resend if needed --- drop if needed 
            #
            log_debug("Check waitQueue++++++++++++++++++++++++++++++++++")
            curTime = time.time()
            for w in waitQueue:
                w.display()
                if curTime - w.time >= 1.0:
                    if w.retry == 4 : # drop and send ICMP err
                        for p in w.ethPktList:
                            ip = IPv4()
                            for intf in my_interfaces:
                                if intf.name == w.srcDevList[w.ethPktList.index(p)]:
                                    ip.src = intf.ipaddr
                            ip.dst = p[p.get_header_index(IPv4)].src
                            ip.ttl = 64
                            ip.protocol = IPProtocol.ICMP
                            icmp = ICMP()
                            icmp.icmptype = ICMPType.ICMPDestinationUnreachable
                            icmp.icmpcode = DestinationUnreachable.HostUnreachable
                            icmpErrPkt = ip + icmp
                            log_debug("send packet on {}".format(str(w.srcDevList[w.ethPktList.index(p)])))
                            self.net.send_packet(w.srcDevList[w.ethPktList.index(p)],icmpErrPkt)
                        del waitQueue[waitQueue.index(w)]
                    else:
                        w.retry += 1
                        w.time = curTime
                        self.net.send_packet(w.dev,w.arpPkt)
                        
def switchy_main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
