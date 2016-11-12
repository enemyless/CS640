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
        self.mappingTable = []
        self.forwardingTableRouter = []
        self.forwardingTable = []
        self.waitQueue = []
        self.my_interface = []

    def setup(self):
        #file = os.path.join(os.path.dirname(__file__),"forwarding_table.txt")
        fp = open("forwarding_table.txt",'r+')

        self.my_interfaces = self.net.interfaces()
        for intf in self.my_interfaces:
            #print(intf)
            self.mappingTable.append(mappingTableElement(intf.ipaddr,intf.ethaddr,intf.name))
            intf_network = str(IPv4Network(int(intf.ipaddr)&int(intf.netmask)))
            intf_net = intf_network.split('/')
            intf_prefix=IPv4Network(str(intf_net[0])+'/'+str(intf.netmask))
            intf_prefixlen = intf_prefix.prefixlen
            
            self.forwardingTable.append(forwardingTableElement(intf_net[0],intf.netmask,None,intf.name,intf_prefixlen))
        #    self.mappingTable[0].display()

        for line in fp:
            line = line.rstrip()
            item = line.split(" ")
            netaddr = IPv4Network(item[0]+'/'+item[1])
            self.forwardingTable.append(forwardingTableElement(item[0],item[1],item[2],item[3],netaddr.prefixlen))
            #self.forwardingTable[0].display()

        self.forwardingTable.sort(key=operator.attrgetter('prefixlen'),reverse=True)

       # for f in self.forwardingTable:
       #     f.display()
       # for f in self.forwardingTableRouter:
       #     f.display()

    def forwardingTableMatch(self,pktSend):
        # longest path comparison
        for f in self.forwardingTable:
            prefixnet = IPv4Network(str(f.prefix) + '/' + str(f.prefixlen))
            match = pktSend[pktSend.get_header_index(IPv4)].dst in prefixnet
            if match:
                return f
        return None

    def mappingTableMatch(self,pktSend,forwardResult):
        # mapping table lookup
        for m in self.mappingTable:
            #m.display()
            #forwardResult.display()
            #forward or network connected directly to the interface
            if forwardResult.nxtHopIP is None:
                if m.ip ==  pktSend[pktSend.get_header_index(IPv4)].dst:
                    return m
            else:
                if str(m.ip) == forwardResult.nxtHopIP:
                    return m
        return None

    def icmpErrPkt(self,icmpRequestPkt,icmptype,icmpcode):
        ip = IPv4()
        #for intf in self.my_interfaces:
        #    if intf.name == dev:
        #        ip.src = intf.ipaddr
        ip.src = "0.0.0.0"
        
        del icmpRequestPkt[icmpRequestPkt.get_header_index(Ethernet)]

        ipv4_header = icmpRequestPkt.get_header(IPv4)
        ip.dst = ipv4_header.src
        ip.ttl = 64
        ip.protocol = IPProtocol.ICMP
        icmp = ICMP()
        icmp.icmptype = icmptype
        icmp.icmpcode = icmpcode 
        icmp.icmpdata.data = icmpRequestPkt.to_bytes()[:28]
        eth = Ethernet()
        eth.ethertype = EtherType.IP
        eth.src = "ff:ff:ff:ff:ff:ff"
        eth.dst = "ff:ff:ff:ff:ff:ff"
        return  eth + ip + icmp


    def icmpRlyPkt(self,icmpRequestPkt):
        eth = Ethernet()
        eth.ethertype = EtherType.IPv4
        eth.src = "ff:ff:ff:ff:ff:ff"
        eth.dst = "ff:ff:ff:ff:ff:ff"
        
        ip = IPv4()
        ip.protocol = IPProtocol.ICMP
        ipv4_header = icmpRequestPkt.get_header(IPv4)
        ip.src = ipv4_header.dst
        ip.dst = ipv4_header.src
        ip.ttl = 64
      
        icmp = ICMP()
        icmp_header = icmpRequestPkt.get_header(ICMP)
        icmp.icmptype = ICMPType.EchoReply
        icmp.icmpdata.data = icmp_header.icmpdata.data
        icmp.icmpdata.identifier = icmp_header.icmpdata.identifier
        icmp.icmpdata.sequence = icmp_header.icmpdata.sequence
        
        return  eth + ip + icmp

    def findIntf(self,dev):
        for intf in self.my_interfaces:
            if intf.name == dev:
                return intf
        return None
    
    def mapAndSend(self,forwardResult,pktSend,dev):
        for intf in self.my_interfaces:
            if intf.name == forwardResult.dev:
                pktSend[pktSend.get_header_index(Ethernet)].src = intf.ethaddr
                if str(pktSend[pktSend.get_header_index(IPv4)].src) == "0.0.0.0": # specific for ICMP err pkt
                    pktSend[pktSend.get_header_index(IPv4)].src = intf.ipaddr
                break
        log_debug("pktSend:{}".format(str(pktSend)))

        mappingResult = self.mappingTableMatch(pktSend,forwardResult) 
        log_debug("mapping result:{}".format(str(mappingResult)))

        if mappingResult is not None:
            #mappingResult.display()
            # send
            #for intf in self.my_interfaces:
            pktSend[pktSend.get_header_index(Ethernet)].dst = mappingResult.mac
            log_debug("send packet on {}".format(str(mappingResult.dev)))
            self.net.send_packet(mappingResult.dev,pktSend)

        else: # no mapping reselt, send ARP request
            for intf in self.my_interfaces:
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
                    for w in self.waitQueue:
                        w_arp_header = w.arpPkt.get_header(Arp)
                        arp_request_header = arp_request.get_header(Arp)
                        if w_arp_header.targetprotoaddr == arp_request_header.targetprotoaddr:
                            w.ethPktList.append(pktSend)
                            insertFlg = 0
                            break
                    if insertFlg == 1:
                        self.waitQueue.append(waitQueueElement(pktSend,arp_request,forwardResult.dev,time.time(),0,dev))
                        log_debug("send packet on {}".format(str(forwardResult.dev)))
                        self.net.send_packet(forwardResult.dev,arp_request)
                    break

    
    def router_main(self):
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        self.setup()
        
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
                        for item in self.mappingTable:
                            #item.display()
                            if item.ip == arp_header.senderprotoaddr:
                                item.mac = arp_header.senderhwaddr
                            #    print ("update")
                                update = 1
                                break
                        if update == 0:
                            self.mappingTable.append(mappingTableElement(arp_header.senderprotoaddr,arp_header.senderhwaddr,dev))

                        for intf in self.my_interfaces:
                            if intf.ipaddr == arp_header.targetprotoaddr:
                                arp_reply = create_ip_arp_reply(intf.ethaddr,arp_header.senderhwaddr,arp_header.targetprotoaddr,arp_header.senderprotoaddr)
                                #print (arp_reply)
                                self.net.send_packet(dev,arp_reply)
                                break
                   
                    # ARP reply
                    elif arp_header.operation == ArpOperation.Reply:
                        log_debug("got arp reply")                
                        self.mappingTable.append(mappingTableElement(arp_header.senderprotoaddr,arp_header.senderhwaddr,dev))
                        for w in self.waitQueue:
                            #w.display()
                            w_arp_header = w.arpPkt.get_header(Arp)
                            if w_arp_header.targetprotoaddr == arp_header.senderprotoaddr:
                                #print("match")
                                for p in w.ethPktList:
                                    p[p.get_header_index(Ethernet)].dst = arp_header.senderhwaddr
                                    #print (p[p.get_header_index(IPv4)].src)
                                    if str(p[p.get_header_index(IPv4)].src) == "0.0.0.0": # specific for ICMP err
                                        p[p.get_header_index(IPv4)].src = self.findIntf(dev).ipaddr
                                    #w.display()
                                    log_debug("send packet on {}".format(str(w.dev)))
                                    self.net.send_packet(w.dev,p) 
                                del self.waitQueue[self.waitQueue.index(w)]
                                break
                
                # ipv4 packet (maybe ICMP or other types)
                ipv4_header = pkt.get_header(IPv4)
                icmp_header = pkt.get_header(ICMP)

                if ipv4_header is not None:
                    pktSend = None
                    sendPort = None
                    log_debug("{}".format(str(ipv4_header)))
                    
                    forwardResult = None
                    mappingResult = None

                    icmpErr = 0
                    
                    # if ICMP request for router interface then send back ICMP reply, else send ICMP ERR 
                    for intf in self.my_interfaces:
                        if intf.ipaddr == ipv4_header.dst:
                            if icmp_header is not None:
                                log_debug("Got a ICMP Header {}".format(str(icmp_header)))
                                if icmp_header.icmptype != ICMPType.EchoRequest:
                                    pktSend = self.icmpErrPkt(pkt,ICMPType.DestinationUnreachable,ICMPCodeDestinationUnreachable.PortUnreachable)
                                    icmpErr = 1
                                else:
                                    pktSend = self.icmpRlyPkt(pkt)
                            else:
                                pktSend = self.icmpErrPkt(pkt,ICMPType.DestinationUnreachable,ICMPCodeDestinationUnreachable.PortUnreachable)
                                icmpErr = 1

                            break

                    if icmpErr == 0 :# no ICMP err
                        log_debug("icmpErr:{}".format(str(icmpErr)))
                        if pktSend is None:# not ICMP for router interface, should be packet to redirect
                            # Construct header
                            pktSend = pkt
                            #print ("aaa")
                            #print (pktSend[pktSend.get_header_index(IPv4)].ttl)
                            #print ("vvv")
                            pktSend[pktSend.get_header_index(IPv4)].ttl -= 1
                            pktSend[pktSend.get_header_index(Ethernet)].src = "ff:ff:ff:ff:ff:ff"
                            pktSend[pktSend.get_header_index(Ethernet)].dst = "ff:ff:ff:ff:ff:ff"
                        
                        log_debug("pktSend:{}".format(str(pktSend)))
                        #print (pktSend[pktSend.get_header_index(IPv4)].dst)
                        forwardResult = self.forwardingTableMatch(pktSend)
                        
                        if forwardResult is None: # ICMP err if no route ro redirect
                            pktSend = self.icmpErrPkt(pkt,ICMPType.DestinationUnreachable,ICMPCodeDestinationUnreachable.NetworkUnreachable)
                            icmpErr = 1
                            log_debug("no route to redirct :pktSend:{}".format(str(pktSend)))

                        elif pktSend[pktSend.get_header_index(IPv4)].ttl == 0: # ICMP err if TTL down to 0
                            pktSend = self.icmpErrPkt(pkt,ICMPType.TimeExceeded,ICMPCodeTimeExceeded.TTLExpired)
                            icmpErr = 1
                            log_debug("TTL expire : pktSend:{}".format(str(pktSend)))
                        
                        log_debug("pktSend:{}".format(str(pktSend)))
                        log_debug("icmpErr:{}".format(str(icmpErr)))

                    if icmpErr == 1:
                        # match forwarding table again for the ICMP err pkt
                        log_debug("pktSend:{}".format(str(pktSend)))
                        forwardResult = self.forwardingTableMatch(pktSend)

                    if forwardResult is not None: #found forwarding result
                        log_debug("forward result:{}".format(str(forwardResult)))
                        #forwardResult.display()
                        self.mapAndSend(forwardResult,pktSend,dev)
                        

            log_debug("Check self.waitQueue++++++++++++++++++++++++++++++++++")
            curTime = time.time()
            for w in self.waitQueue:
                #w.display()
                if curTime - w.time >= 1.0:
                    if w.retry == 4 : # drop and send ICMP err
                        for p in w.ethPktList:
                            icmp_header = p.get_header(ICMP)
                            if icmp_header is None or icmp_header.icmpcode != ICMPCodeDestinationUnreachable.HostUnreachable:
                                pktSend = self.icmpErrPkt(p,ICMPType.DestinationUnreachable,ICMPCodeDestinationUnreachable.HostUnreachable)
                                forwardResult = self.forwardingTableMatch(pktSend)
                                log_debug("forward result2:{}".format(str(forwardResult)))
                                #forwardResult.display()
                                if forwardResult is not None: #found forwarding result
                                    log_debug("forward result:{}".format(str(forwardResult)))
                                    #forwardResult.display()
                                    #pktSend = self.icmpErrPkt(p,ICMPType.DestinationUnreachable,ICMPCodeDestinationUnreachable.HostUnreachable)
                                    self.mapAndSend(forwardResult,pktSend,dev)
                        del self.waitQueue[self.waitQueue.index(w)]
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
