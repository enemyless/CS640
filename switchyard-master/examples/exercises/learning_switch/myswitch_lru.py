#!/usr/bin/env python3

'''
Ethernet learning switch in Python: HW3.
'''
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *

class switchTableElement(object):
    def __init__(self,mac=None,dev=None):
        self.mac = mac
        self.dev = dev

    def display(self):
        print ("mac=%s,dev=%s\n" % (self.mac,self.dev))

def switchy_main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    itemCnt = 0    
    maxCnt = 5
    switchTable = []
    #for i in range(0,5):
    #    switchTable.append(switchTableElement())
    #    switchTable[i].display()
    # print (switchTable)

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
                update=1
                break

        if update == 0:
            if itemCnt != maxCnt:
                itemCnt = itemCnt + 1
            else:
                del switchTable[-1]
            
            switchTable.insert(0,switchTableElement(packet[0].src,dev))

        log_debug ("In {} received packet {} on {}".format(net.name, packet, dev))
        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
        else:
            flood = 1
            for item in switchTable:
                if item.mac == packet[0].dst:
                    log_debug ("Directly send packet {} to {}".format(packet, item.dev))
                    tmp = item
                    switchTable.remove(item)
                    switchTable.insert(0,tmp)
                    net.send_packet(item.dev, packet)
                    flood = 0
                    break
            
            if flood == 1:       
                for intf in my_interfaces:
                    if dev != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)
#        for item in switchTable:
#            item.display()
#        print ("itemCnt=%d\n---------------\n" % itemCnt)    
    net.shutdown()
