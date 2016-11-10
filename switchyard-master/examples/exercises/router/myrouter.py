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

     #           ipv4_header = pkt.get_header(IPv4)
     #           if ipv4_header is not None:
     #               # for the router itself
     #               dstRounter = 0;
     #               for intf in my_interfaces:
     #                   if intf.ipaddr == ipv4_header.dst:
     #                       dstRounter = 1
     #                       break

     #               if dstRounter = 1:
     #                   continue # go back to receive packet

     #               # longest path comparison
     #               forwardResult = None
     #               for f in forwardingTable:
     #                   prefixnet = IPv4Network(f.prefix + '/' + f.prefixlen)
     #                   match = ipv4_header.dst in prefixnet
     #                   if match:
     #                       forwardResult = f
     #                       break

     #               if forwardResult = None:
     #                   continue # not in the forwarding table

                    






     #               netaddr = IPv4Network()
                    

                    
                    
def switchy_main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net)
    r.router_main()
    net.shutdown()
