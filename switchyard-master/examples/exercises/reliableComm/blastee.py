#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from threading import *
import time
import re
import os

def switchy_main(net):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    myips = [intf.ipaddr for intf in my_interfaces]
    myip = myips[0]

    script_dir = os.path.dirname(__file__)
    filename = "blastee_params.txt"
    fp = open(os.path.join(script_dir,filename),'r+')
    blaster_IP = None
    pktNum = 0
    pktList = []
    for line in fp:
        log_debug("line:{}".format(line))
        m = re.search(".*-b\s+([^ \t]+)",line)
        if m:
            blaster_IP = m.group(1)
            log_debug("blaster_IP:{}".format(blaster_IP))
            
        m = re.search(r"-n\s+([^ \t]+)",line)
        if m:
            pktNum = int(m.group(1))
            log_debug("pktNum:{}".format(pktNum))

    while True:
        gotpkt = True
        try:
            dev,pkt = net.recv_packet()
            log_debug("Device is {}".format(dev))
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("I got a packet from {}".format(dev))
            log_debug("Pkt: {}".format(pkt))

            seqNumRaw = pkt[3].to_bytes()[0:4]
            seqNum = int.from_bytes(seqNumRaw,byteorder='big')
            if seqNum not in pktList:
                pktList += [seqNum]
            log_debug("seqNum:{}".format(seqNum))
            
            payloadLen = int.from_bytes(pkt[3].to_bytes()[4:6],byteorder='big')

            payload = None
            if payloadLen >= 8:
                payload = pkt[3].to_bytes()[6:14]
            else:
                payload = pkt[3].to_bytes()[6:6+payloadLen]
                for i in range(8-payloadLen) :
                    payload += b'\x00'

            rawdata = seqNumRaw + payload
            ethsrc = pkt[pkt.get_header_index(Ethernet)].dst
            pkt[pkt.get_header_index(Ethernet)].src = ethsrc
            
            ethdst = pkt[pkt.get_header_index(Ethernet)].src
            pkt[pkt.get_header_index(Ethernet)].dst = ethdst

            #ipsrc = pkt[pkt.get_header_index(IPv4)].dst
            pkt[pkt.get_header_index(IPv4)].src = myip

            #ipdst = pkt[pkt.get_header_index(IPv4)].src
            pkt[pkt.get_header_index(IPv4)].dst = blaster_IP

            pktSend = pkt[0]+pkt[1]+pkt[2]+rawdata
            net.send_packet(dev, pktSend)
            log_debug("pktList:{}".format(pktList))
            log_debug("pktlen:{}".format(len(pktList)))
            if len(pktList)==pktNum:
                break

#a=12234567
#b=a.to_bytes(4,'big')       b=b'\x00\x12\xd6\x87'
#c=b[1:2]                    c=b'\x12'
#d=int.from_bytes(c,byteorder='big')    d=18

    net.shutdown()
