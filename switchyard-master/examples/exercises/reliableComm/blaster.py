#!/usr/bin/env python3

from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.common import *
from random import randint
import time
import re
import os

def sendPkt(net,seqNum,myip,blastee_IP,payloadLen):
    pkt = Ethernet() + IPv4() + UDP()
    pkt[1].protocol = IPProtocol.UDP
    pkt[0].src = "10:00:00:00:00:01"
    pkt[0].dst = "40:00:00:00:00:01"
    pkt[1].src = myip
    pkt[1].dst = blastee_IP
    pkt[2].srcport = 4444
    pkt[2].dstport = 5555
    raw = seqNum.to_bytes(4,'big')+payloadLen.to_bytes(2,'big')
    for i in range(payloadLen):
        raw += b'\xab'
    pkt += raw
    net.send_packet("blaster-eth0", pkt)

def switchy_main(net):
    my_intf = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_intf]
    myips = [intf.ipaddr for intf in my_intf]
    myip = myips[0]
    pktList=[]
    retranList=[]

    script_dir = os.path.dirname(__file__)
    filename = "blaster_params.txt"
    fp = open(os.path.join(script_dir,filename),'r+')
    blastee_IP = None
    pktNum = 0
    payloadLen = 0
    senderWin = 0
    timeout = 0
    rcvTimeout = 0
    LHS = 0
    RHS = 0
    startTime = 0
    pkt_ptr = 1
    retransNum = 0
    retransNum1 = 0
    coarseTONum = 0
    totalTransNum = 0
    retranListAll = []

    for line in fp:
        m = re.search("-b\s+([^ \t]+)",line)
        if m:
            blastee_IP = m.group(1)
            log_debug("blastee_IP:{}".format(blastee_IP))
            
        m = re.search("-n\s+([^ \t]+)",line)
        if m:
            pktNum = int(m.group(1))
            log_debug("pktNum:{}".format(pktNum))
            
        m = re.search("-l\s+([^ \t]+)",line)
        if m:
            payloadLen = int(m.group(1))
            log_debug("payloadLen:{}".format(payloadLen))
            
        m = re.search("-w\s+([^ \t]+)",line)
        if m:
            senderWin = int(m.group(1))
            log_debug("senderWin:{}".format(senderWin))
            
        m = re.search("-t\s+([^ \t]+)",line)
        if m:
            timeout = float(m.group(1))
            log_debug("timeout:{}".format(timeout))
            
        m = re.search("-r\s+([^ \t]+)",line)
        if m:
            rcvTimeout = float(m.group(1))
            log_debug("rcvTimeout:{}".format(rcvTimeout))

        startTimeFirst = time.time()
        startTime = time.time()
    while True:
        gotpkt = True
        try:
            #Timeout value will be parameterized!
            dev,pkt = net.recv_packet(timeout=rcvTimeout/1000)
            #dev,pkt = net.recv_packet(timeout=1)
        except NoPackets:
            log_debug("No packets available in recv_packet")
            gotpkt = False
        except Shutdown:
            log_debug("Got shutdown signal")
            break

        if gotpkt:
            log_debug("----------------------I got a packet---------------------------")
            log_debug("just received pkt")
            log_debug("LHS:{},RHS:{},pkt_ptr:{},startTime:{}".format(LHS,RHS,pkt_ptr,startTime))
            log_debug("pktList:{}".format(pktList))
            log_debug("retranList:{}".format(retranList))

            seqNum = int.from_bytes(pkt[3].to_bytes()[0:4],byteorder='big')
            log_debug("seqNum:{}".format(seqNum))
            if seqNum in pktList:
                pktList.remove(seqNum)
                if not pktList and not retranList and pkt_ptr == pktNum+1 : 
                    break
                if LHS == seqNum:
                  #  if LHS == pktNum:
                  #      break
                    if pktList:
                        LHS = pktList[0]
                    else:
                        LHS = 0
                        RHS = 0
                    startTime = time.time()

            log_debug("after update for receive pkt")
            log_debug("LHS:{},RHS:{},pkt_ptr:{},startTime:{}".format(LHS,RHS,pkt_ptr,startTime))
            log_debug("pktList:{}".format(pktList))
            log_debug("retranList:{}".format(retranList))
        else:
            log_debug("+++++++++++++++++++++++Didn't receive anything+++++++++++++++++++")
            log_debug("Before send")
            log_debug("LHS:{},RHS:{},pkt_ptr:{},startTime:{}".format(LHS,RHS,pkt_ptr,startTime))
            log_debug("pktList:{}".format(pktList))
            log_debug("retranList:{}".format(retranList))
                
            # timeout logic
            curTime = time.time()
            if curTime-startTime > timeout/1000 :
                coarseTONum += 1
                log_debug("$$$$$$$$$$TIMEOUT$$$$$$")
                retransNum += len(pktList)
                retranList += pktList
                retranListAll += pktList
                retranListAll = list(set(retranListAll))
                pktList = []
                retranList.sort()
                RHS = 0
                LHS = 0

           # if RHS-LHS < senderWin-1 or (LHS==0 and RHS==0): # sender window is not full
                # RHS==0 LHS==0 is special case for sendWin=1
            if retranList: # retrans list not empty, send first
                if (retranList[0]-LHS+1 <= senderWin) or (LHS==0):
                    sendPkt(net,retranList[0],myip,blastee_IP,payloadLen)
                    totalTransNum += 1
                    retransNum1+=1
                    if LHS == 0:
                        LHS = retranList[0]
                        startTime = time.time()
                    RHS = retranList[0]
                    pktList.append(retranList[0])
                    del retranList[0]
            elif pkt_ptr <= pktNum: #retran list empty, test if the max pkt seq number reached
                if (pkt_ptr-LHS+1 <= senderWin) or (LHS==0):
                    sendPkt(net,pkt_ptr,myip,blastee_IP,payloadLen)
                    totalTransNum += 1
                    if LHS == 0:
                        LHS = pkt_ptr
                        startTime = time.time()
                    RHS = pkt_ptr
                    pktList.append(pkt_ptr)
                    pkt_ptr += 1

            log_debug("After send")
            log_debug("LHS:{},RHS:{},pkt_ptr:{},startTime:{}".format(LHS,RHS,pkt_ptr,startTime))
            log_debug("pktList:{}".format(pktList))
            log_debug("retranList:{}".format(retranList))


    totalTime = time.time()-startTimeFirst;
    throughput = payloadLen*totalTransNum/totalTime
    goodput = payloadLen*(pktNum-len(retranListAll))/totalTime

    print("Total TX Time : {} seconds".format(totalTime))
    print("Number of reTX : {}".format(retransNum))
   # print("Number of reTX : {}".format(retransNum1))
    print("Number of coarse TimeOut : {}".format(coarseTONum))
    print("Throughput(Bps) : {}".format(throughput))
    print("Goodput(Bps) : {}".format(goodput))
    net.shutdown()
