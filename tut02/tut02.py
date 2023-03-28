import os
from scapy.all import *

# BEFORE RUNNING THE PROGRAM PING A WEBSITE SO THAT ARP PACKETS ARE CAPTURED

def ARP():
    packets = sniff(filter="arp", timeout = 2)
    print(packets.summary())
    wrpcap("./output/ARP_2001CS70.pcap", packets)


def DNS_request_response():
    dns_req = IP(dst="8.8.8.8")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="http://icicibank.com"))
    dns_res = sr1(dns_req, verbose=1)
    ans = PcapWriter("./output/DNS_request_response_2001CS70.pcap",append=True,sync=True)
    ans.write(dns_req)
    ans.write(dns_res)


def PING_request_response():
    packet = IP(dst="http://icicibank.com")/ICMP()
    answer = sr1(packet)
    ans = PcapWriter("./output/PING_request_response_2001CS70.pcap",sync=True,append=True)
    ans.write(packet)
    ans.write(answer)


def TCP_3_way_handshake_start():
    ip = IP(src="10.0.2.7", dst="20.204.105.107")
    SYN = TCP(sport=1500, dport=80, flags="S", seq=100)
    SYNACK = sr1(ip/SYN)
    ACK = TCP(sport=1500, dport=80, flags="A", seq=101, ack=SYNACK.seq+1)
    send(ip/ACK)
    ans = PcapWriter("./output/TCP_3_way_handshake_start_2001CS70.pcap",sync=True,append=True)
    ans.write(SYN)
    ans.write(SYNACK)
    ans.write(ACK)


def ARP_request_response():
    packet=IP(dst="172.16.179.78")/ICMP()
    answer=sr1(packet)
    ans = PcapWriter("./output/ARP_request_response_2001CS70.pcap",sync=True,append=True)
    ans.write(packet)
    ans.write(answer)



ARP()
DNS_request_response()
PING_request_response()
TCP_3_way_handshake_start()
ARP_request_response()