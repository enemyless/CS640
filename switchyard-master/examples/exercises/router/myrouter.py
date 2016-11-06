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

class mapingTableElement(object):
    def __init__(self,ip=None,mac=None,TTL=64):
        self.ip = ip
        self.mac = mac
        self.TTL = TTL

    def display(self):
        print ("ip=%s,mac=%s,TTL=%s\n" % (self.ip,self.mac,self.TTL))

class Router(object):
    def __init__(self, net):
        self.net = net
        self.mappingTable = []
        # other initialization stuff here


    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        my_interfaces = self.net.interfaces()

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

                # ARP packet
                arp_header = pkt.header(Arp)
                    if arp_header:

                    # ARP request
                    if arp_header.targethwaddr == "":
                        for item in mappingTable:
                            if item.ip == arp_header.senderprotoaddr:
                                item.mac = arp_header.senderhwaddr
                                break

                        for item in my_interfaces:
                            if item.ipaddr == arp_header.targetprotoaddr:
                                arp_reply == create_ip_art_reply(arp_header.senderhwaddr,arp_header.targethwaddr,arp_header.senderprotoaddr,arp_header.targetprotoaddr)
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
