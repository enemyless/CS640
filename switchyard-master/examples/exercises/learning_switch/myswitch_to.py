#!/usr/bin/env python3

'''
Ethernet learning switch in Python: HW3.
'''
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
import time

class switchTableElement(object):
    def __init__(self,mac=None,dev=None,time=None):
        self.mac = mac
        self.dev = dev
        self.time = time

    def display(self):
        print ("mac=%s,dev=%s,time=%s\n" % (self.mac,self.dev,self.time))

def switchy_main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    switchTable = []
    

    while True:
        try:
            dev,packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            return

        curTime = time.time();
        #print ("%f\n" % (curTime))
        for item in switchTable:
            if curTime - item.time >= 10.0:
                switchTable.remove(item);
        update = 0
        for item in switchTable:
            if item.mac == packet[0].src:
                item.dev = dev
                item.time = curTime
                update=1
                break

        if update == 0:
            switchTable.insert(0,switchTableElement(packet[0].src,dev,curTime))

        #for item in switchTable:
        #    item.display()
            
        log_debug ("In {} received packet {} on {}".format(net.name, packet, dev))
        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
        else:
            flood = 1
            for item in switchTable:
                if item.mac == packet[0].dst:
                    log_debug ("Directly send packet {} to {}".format(packet, item.dev))
                    net.send_packet(item.dev, packet)
                    flood = 0
                    break
            
            if flood == 1:       
                for intf in my_interfaces:
                    if dev != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
    net.shutdown()
