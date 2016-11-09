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

class mappingTableElement(object):
    def __init__(self,ip=None,mac=None,TTL=64):
        self.ip = ip
        self.mac = mac
        self.TTL = TTL

    def display(self):
        print ("ip=%s,mac=%s,TTL=%s\n" % (self.ip,self.mac,self.TTL))

class forwardingTableElement(object):
    def __init__(self,prefix=None,netmask=None,nxtHopIP=None,dev=None):
        self.prefix = prefix
        self.netmask = netmask
        self.nxtHopIP = nxtHopIP
        self.dev = dev

    def display(self):
        print ("prefix=%s,netmask=%s,nxtHopIP=%s,dev=%s\n" % (self.prefix,self.netmask,self.nxtHopIP,self.dev))


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
        forwardingTable = []
        file = os.path.join(os.path.dirname(__file__),"forwarding_table.txt")
        fp = open(file,'r+')

        my_interfaces = self.net.interfaces()
        for intf in my_interfaces:
            print(intf)
            mappingTable.insert(0,mappingTableElement(intf.ipaddr,intf.ethaddr,intf.name))
        #    mappingTable[0].display()

        for line in fp:
            line = line.rstrip()
            item = line.split(" ")
            forwardingTable.insert(0,forwardingTableElement(item[0],item[1],item[2],item[3]))
            forwardingTable[0].display()

        
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

                    
                    
def switchy_main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
