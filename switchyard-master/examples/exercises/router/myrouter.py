#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import sys
import os
import time
from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.common import *
import operator

class mappingTableElement(object):
    def __init__(self,ip=None,mac=None,TTL=64):
        self.ip = ip
        self.mac = mac
        self.TTL = TTL

    def display(self):
        print ("ip=%s,mac=%s,TTL=%s\n" % (self.ip,self.mac,self.TTL))

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
    def __init__(self,ethPkt=None,arpPkt=None,dev=None,time=0,retry=0):
        self.ethPkt = ethPkt
        self.arpPkt = arpPkt
        self.dev = dev
        self.time = time
        self.retry = retry


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
            intf_prefix=IPv4Network(intf_net[0]+'/'+str(intf.netmask))
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
                log_debug("Got a packet: {}".format(str(pkt)))

                print ("got a packet")
                print (pkt)
                # ARP packet
                arp_header = pkt.get_header(Arp)
                print (arp_header)                
                # ARP request
                if arp_header is not None:
                    if arp_header.operation == ArpOperation.Request:
                        update=0
                        for item in mappingTable:
                            item.display()
                            if item.ip == arp_header.senderprotoaddr:
                                item.mac = arp_header.senderhwaddr
                            #    print ("update")
                                update = 1
                                break
                        if update == 0:
                            mappingTable.insert(0,mappingTableElement(arp_header.senderprotoaddr,arp_header.senderhwaddr))
                        for intf in my_interfaces:
                            if intf.ipaddr == arp_header.targetprotoaddr:
                                arp_reply = create_ip_arp_reply(intf.ethaddr,arp_header.senderhwaddr,arp_header.targetprotoaddr,arp_header.senderprotoaddr)
                                print (arp_reply)
                                self.net.send_packet(dev,arp_reply)
                                break

                    else if arp_header.operator == ArpOperation.Reply:
                        mappingTable.insert(0,mappingTableElement(arp_header.senderprotoaddr,arp_header.senderhwaddr))
                        for p in waitQueue:
                            if p.arpPkt.targetprotoaddr == arp_header.senderprotoaddr:
                                p.ethPkt[0].dst = arp_header.senderhwaddr
                                self.net.send_packet(p.dev,p.ethPkt) 
                                break

                ipv4_header = pkt.get_header(IPv4)
                if ipv4_header is not None:
                    # for the router itself
                    dstRouter = 0;
                    forwardResult = None
                    mappingResult = None
                    
                    for intf in my_interfaces:
                        if intf.ipaddr == ipv4_header.dst:
                            dstRouter = 1
                            break

                    if dstRouter != 1:
                        # longest path comparison
                        for f in forwardingTable:
                            prefixnet = IPv4Network(f.prefix + '/' + f.prefixlen)
                            match = ipv4_header.dst in prefixnet
                            if match:
                                forwardResult = f
                                break

                    if forwardResult is not None:
                        # mapping table lookup
                        for m in mappingTable:
                            if m.ip == f.nxtHopIP:
                                mappingResult = m
                                break
                        
                        # Construct header
                        ipv4_header.ttl--
                        eth_header = Ethernet()
                        if intf.name == forwardingResult.dev:
                            eth_header.src = intf.ethaddr
                            break
                        eth_header.dst = None
                        eth_header.ethertype = EtherType.IPv4
                        p = eth_header + ipv4_header
                        
                        if mappingResult is not None:
                            # send
                            for intf in my_interfaces:
                                p[0].dst = mappingResult.mac
                                self.net.send_packet(m.dev,p)

                        else:
                            # ARP request
                            for intf in my_interfaces:
                                if intf.name == forwardingResult.dev:
                                    arp_request = create_ip_arp_request(eth_header.src,intf.ipaddr,forwardingResult.nxtHopIP)
                                    self.net.send_packet(forwardingResult.dev,arp_request)
                                    waitQueue.insert(0,waitQueueElement(p,arp_request,forwardingResult.dev,time.time(),0))
                                    break


                #ICMP
                #icmp_header = xxxxx

            # Check Queue
            # periodically check queue.
            # 1. if found mapping item in mappin g table, then send
            # 2. check ARP status -- resend if needed --- drop if needed 
            #
            curTime = time.time()
            for p in waitQueue:
                if p.time - curTime >= 1.0:
                    if p.retry == 5 : # drop
                        del p
                    else
                        p.retry++
                        p.time = curTime
                        self.net.send_packet(p.dev,p.arpPkt)
                        
                    
#def longestPathMatch
        

                    
                    
def switchy_main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
