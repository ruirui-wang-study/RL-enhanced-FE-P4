# Imports
import datetime
import time
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP

# print(os.path.isfile(r'..\Data\dataset\pcap\bulk_xs_02.pcap'))  #查看该文件是否存在

srcfile = r"..\Data\dataset\pcap\nonTor\browsing_ara2.pcap"
dstfile = r"..\Data\dataset\csv\nonTor\Browsing_ara2.csv"


# Required internal vars
pkt_count = 0
buffer_count = 0
verbose_count = 0
data_buffer = []
verbose = True
vbuffer = 5000
wbuffer = 5000
skip_empty = 'no'
with open(dstfile, 'w') as dst:
    #dst.write('time,proto,data_len,ip_src,ip_dst,src_port,dst_port\n')
    dst.write('time,etherType,proto,data_len,ip_src,ip_dst,src_port,dst_port\n')

    # READ THE PCAP FILE
    for pkt_data in RawPcapReader(srcfile):
        ether_pkt = Ether(pkt_data)
        if 'type' not in ether_pkt.fields: continue  # LLC frames will have 'len' instead of 'type'.
        if ether_pkt.type != 0x0800: continue  # disregard non-IPv4 packets

        ip_pkt = ether_pkt[IP]

        if ip_pkt.proto == 6 or ip_pkt.proto == 17:  # if UDP or TCP
            pkt = ip_pkt[TCP if ip_pkt.proto == 6 else UDP]
            data_len = (len(pkt) - (pkt.dataofs * 4)) if (ip_pkt.proto == 6) else len(pkt)
            sport, dport = ip_pkt.payload.sport, ip_pkt.payload.dport
        else:  # if other IP packet
            continue  # filter non TCP-UDP packets
        # data_len = len(ip_pkt)
        # sport, dport = '', ''
        if skip_empty and data_len == 0: continue  # Skip packets with an empty payload

        pkt_timestamp = ip_pkt.payload.time

        # GET THE CSV LINE FOR THE ACTUAL PACKET
        # pkt_timestamp = (pkt_metadata.sec) + (pkt_metadata.usec / 1000000)
        pkt_line = '{},{},{},{},{},{},{},{}'.format(
            pkt_timestamp,ether_pkt.type, ip_pkt.proto, data_len,
            ip_pkt.src, ip_pkt.dst,
            sport, dport
        )
        # REFRESH INTERNAL VARIABLES
        pkt_count += 1
        verbose_count += 1
        buffer_count += 1
        data_buffer.append(pkt_line)

        # PRINT THE PROGRESS AND RESET THE COUNTER
        if verbose and verbose_count >= vbuffer:
            print('Parsed packets : {}'.format(pkt_count), end='\r')
            verbose_count = 0

        # WRITE TO THE CSV FILE AND RESET COUNTER AND BUFFER
        if buffer_count >= wbuffer:
            dst.write('{}\n'.format('\n'.join(data_buffer)))
            buffer_count = 0
            data_buffer = []

        # PUSH THE LAST LINES IF THEY DID NOT REACH THE BUFFER WRITTING THRESHOLD
    if buffer_count > 0:
        dst.write('{}\n'.format('\n'.join(data_buffer)))
        if verbose: print('Parsed packets : {}'.format(pkt_count))

if verbose: print('Parse finished, csv file in {}'.format(dstfile))