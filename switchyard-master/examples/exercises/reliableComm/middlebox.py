#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from threading import *
import random
import time
import re
import os

def switchy_main(net):

    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]

    script_dir = os.path.dirname(__file__)
    filename = "middlebox_params.txt"
    fp = open(os.path.join(script_dir,filename),'r+')
    drop_rate = 0
    drop_num = 0
    total_num = 0
    for line in fp:
        m = re.search("-d\s+([^ \t]+)",line)
        if m:
            drop_rate = float(m.group(1))
            log_debug("drop_rate:{}".format(drop_rate))

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
            log_debug("I got a packet {}".format(pkt))
            log_debug("total_num: {}".format(total_num))
            log_debug("drop_num: {}".format(drop_num))

        if dev == "middlebox-eth0":
            log_debug("Received from blaster")
            '''
            Received data packet
            Should I drop it?
            If not, modify headers & send to blastee
            '''

            seqNum = int.from_bytes(pkt[3].to_bytes()[0:4],byteorder='big')
            rand = random.random()
            total_num += 1
            if rand < drop_rate:
                log_debug("seqNum:{} dropped".format(seqNum))
                drop_num += 1
                continue

            log_debug("seqNum:{} pass to blastee".format(seqNum))
            pkt[pkt.get_header_index(Ethernet)].src = "40:00:00:00:00:02"
            pkt[pkt.get_header_index(Ethernet)].dst = "20:00:00:00:00:01"
            
            net.send_packet("middlebox-eth1", pkt)

        elif dev == "middlebox-eth1":
            log_debug("Received from blastee")
            '''
            Received ACK
            Modify headers & send to blaster. Not dropping ACK packets!
            net.send_packet("middlebox-eth0", pkt)
            '''
            
            pkt[pkt.get_header_index(Ethernet)].src = "40:00:00:00:00:01"
            pkt[pkt.get_header_index(Ethernet)].dst = "10:00:00:00:00:01"
            net.send_packet("middlebox-eth0", pkt)

        else:
            log_debug("Oops :))")

    net.shutdown()
