# -*- coding: UTF-8 -*-
import dpkt
import socket
import datetime
import matplotlib.pyplot as plt
import numpy as np
FILE_NAME = 'UltimateFile.pcap'
SOURCE_IP = "140.113.195.91"
PORT_1 = 39286
PORT_2 = 39288

first_loop = 0
ini_trans_time = 0

first = 0
first_ts = 0
first_seq = 0

second = 0
second_ts = 0
second_seq = 0

def printPcap(pcap):
    global first_loop
    global ini_trans_time

    global first
    global first_ts
    global first_seq

    global second
    global second_ts
    global second_seq

    list_ts_1 = []
    list_sqn_1 = []
    list_pkgsize_1 = []

    list_ts_2 = []
    list_sqn_2 = []
    list_pkgsize_2 = []

    time_interval = 0.05
    time_interval_count = 0

 
    pkgsize_cumulator_1 = 0
    pkgsize_cumulator_2 = 0

    for (ts,buf) in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        if not isinstance(eth.data, dpkt.ip.IP):
            print 'Non IP Packet type not supported %s' % eth.data.__class__.__name__
            continue

        ip = eth.data
        src = socket.inet_ntoa(ip.src)
        dst = socket.inet_ntoa(ip.dst)

        tcp = ip.data
        if first_loop == 0 and (src == SOURCE_IP and tcp.dport == PORT_1 or src == SOURCE_IP and tcp.dport == PORT_2):
            first_loop = 1
            ini_trans_time = ts
        ###############  Debug  ####################
        #if time_interval_count == 1:
        #    print "I was once one"
        #if ts - ini_trans_time <= 1.0:
            #print time_interval_count
            #print ts - ini_trans_time
        ############################################  
        if (time_interval * time_interval_count) <=  (ts - ini_trans_time) and (ts - ini_trans_time) < (time_interval * time_interval_count)+time_interval:
            if src == SOURCE_IP and tcp.dport == PORT_1:
                pkgsize_cumulator_1 = pkgsize_cumulator_1 + len(buf)
                
            if src == SOURCE_IP and tcp.dport == PORT_2:
                pkgsize_cumulator_2 = pkgsize_cumulator_2 + len(buf)
        elif (ts - ini_trans_time) >= (time_interval * time_interval_count)+time_interval and first_loop == 1 :
            time_interval_count = time_interval_count + 1

            list_pkgsize_1.append(pkgsize_cumulator_1/time_interval)
            list_pkgsize_2.append(pkgsize_cumulator_2/time_interval)

            pkgsize_cumulator_1 = 0
            pkgsize_cumulator_2 = 0
            if src == SOURCE_IP and tcp.dport == PORT_1:
                pkgsize_cumulator_1 = pkgsize_cumulator_1 + len(buf)
            if src == SOURCE_IP and tcp.dport == PORT_2:
                pkgsize_cumulator_2 = pkgsize_cumulator_2 + len(buf)
            #print time_interval_count
            #print ts - ini_trans_time






        if src == SOURCE_IP and tcp.dport == PORT_1:
            if first == 0:
                first = 1
                first_ts = ts
                first_seq = tcp.seq

            #print '[+] Src:'+src+' -->Dst:'+dst +  '\tseq: ' + str(tcp.seq-first_seq) + '  \ttime:' + format(ts-first_ts, '.6f') + '\tsize: ' + str(len(buf))

            list_ts_1.append(ts-first_ts)
            list_sqn_1.append( tcp.seq-first_seq)

        if src == SOURCE_IP and tcp.dport == PORT_2:
            if second == 0:
                second = 1
                second_ts = ts
                second_seq = tcp.seq

            #print '[+] Src:'+src+' -->Dst:'+dst +  '\tseq: ' + str(tcp.seq-second_seq) + '  \ttime:' + format(ts-second_ts, '.6f') + '\tsize: ' + str(len(buf))

            list_ts_2.append(ts-second_ts)
            list_sqn_2.append(tcp	.seq-second_seq)

    list_pkgsize_1.append(pkgsize_cumulator_1/time_interval)
    list_pkgsize_2.append(pkgsize_cumulator_2/time_interval)

    #print time_interval_count
    lineSpace =  np.linspace(0, time_interval_count, time_interval_count+1).tolist()
    #print lineSpace
    #print list_pkgsize_1
    #Sprint list_pkgsize_2
    #print time_interval_count	
    #draw_sqn(list_ts_1, list_sqn_1, list_ts_2, list_sqn_2)
    draw_pkgsize(list_pkgsize_1, list_pkgsize_2, lineSpace)

def draw_pkgsize(list_pkgsize_1, list_pkgsize_2, lineSpace):
    plt.plot(lineSpace, list_pkgsize_1, 'r')
    plt.plot(lineSpace, list_pkgsize_2, 'b')
    plt.xlabel("Time");	
    plt.ylabel("Packet Size");
    plt.title("graph")
    plt.show()


def draw_sqn(list_ts_1,list_sqn_1, list_ts_2, list_sqn_2):
    plt.plot(list_ts_1, list_sqn_1, 'r')
    plt.plot(list_ts_2, list_sqn_2, 'b')
    plt.xlabel("Time");	
    plt.ylabel("Sequence Number");
    plt.title("time/sequence graph")
    plt.show()

def main():
    f = open(FILE_NAME)
    pcap = dpkt.pcap.Reader(f)
    printPcap(pcap)

if __name__ == '__main__':
    main()
