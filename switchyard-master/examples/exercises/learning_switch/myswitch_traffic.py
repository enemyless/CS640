#!/usr/bin/env python3

'''
Ethernet learning switch in Python: HW3.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
import operator

class switchTableElement(object):
    def __init__(self,mac=None,dev=None):
        self.mac = mac
        self.dev = dev
        self.traffic = 0

    def display(self):
        print ("mac=%s,dev=%s,traffic=%s\n" % (self.mac,self.dev,self.traffic))

def switchy_main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    itemCnt = 0    
    maxCnt = 5
    switchTable = []

    while True:
        try:
            dev,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        update=0
        for item in switchTable:
            if item.mac == packet[0].src:
                item.dev = dev
                item.traffic += 1
                update=1
                break

        if update == 0:
            if itemCnt != maxCnt:
                itemCnt = itemCnt + 1
            else:
                switchTable.sort(key=operator.attrgetter('traffic'))
                del switchTable[0]
            
            switchTable.insert(0,switchTableElement(packet[0].src,dev))

        for item in switchTable:
            item.display()
        print ("itemCnt=%d" % itemCnt)
            
        log_debug ("In {} received packet {} on {}".format(net.name, packet, dev))
        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
        else:
            flood = 1
            for item in switchTable:
                if item.mac == packet[0].dst:
                    log_debug ("Directly send packet {} to {}".format(packet, item.dev))
                    item.traffic += 1
                    net.send_packet(item.dev, packet)
                    flood = 0
                    break
            
            if flood == 1 :       
                for intf in my_interfaces:
                    if dev != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
    net.shutdown()
