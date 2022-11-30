# Implementing ARP Spoof Attack Detection Using Scapy
from scapy.all import *
from getmac import get_mac_address
from scapy.layers.l2 import ARP, Ether
import os
from collections import Counter
import easygui
import subprocess
# import modules
import scapy.all as scapy
import os
# importing libraries from scapy
from getmac import get_mac_address
from scapy.all import Ether, ARP, srp, conf
import os
a = []
b = []
c = []
d = []
count = 0
attacker_ip = ""
real_mac = ""
flag = False
i=1
os.system("arp -a > f1")
with open("f1", 'r') as f:
    for line in f:
        if (i==4):
            line1 = line.split()
            print(line1,".......")
            a.append(line1[1])
            b.append(line1[2])
        i+=1

def mac(ipadd):
    # requesting arp packets from the IP address
    # if it's wrong then will throw error
    arp_request = scapy.ARP(pdst=ipadd)
    br = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_br = br / arp_request
    list_1 = scapy.srp(arp_req_br, timeout=5,
                       verbose=False)[0]
    print(list_1[0][1])
    return list_1[0][1].hwsrc

# taking interface of the system as an argument
# to sniff packets inside the network


def sniff(interface):
    # store=False tells sniff() function
    # to discard sniffed packets
    scapy.sniff(iface='Enter your network interface', store=False,
               prn=process_sniffed_packet)
    
    pkts = scapy.sniff(filter="arp", iface=interface, count=10)
    print(pkts.summary())
    print(".......")

pkt_sniff = scapy.sniff(filter="arp", timeout=10)
for pkt in pkt_sniff:
    if pkt[ARP].op == 2: # and pkt[Ether].dst == get_mac_address():
        c.append(pkt[ARP].psrc)
        d.append(pkt[Ether].src)
print(c)
if len(pkt_sniff) * 0.7 <= len(c):
    count += 1
    print("test_2: ")
    print(list(zip(c,d)))

if len(c) !=0:
    if Counter(c).most_common(1)[0][1] > 3:
        attacker_ip = Counter(c).most_common(1)[0][0]
        count += 1
        print("test_3 ")

# defining function to process sniffed packet
def process_sniffed_packet(packet):
    print("hi")
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        originalmac = a[0]
        responsemac = packet[scapy.ARP].hwsrc
        print(originalmac, responsemac)
        if (originalmac != responsemac):
            print("[*] ALERT!!! You are under attack, ARP table is being poisoned.!")


# machine interface is "eth0", sniffing the interface
#enable_ip_route()
sniff('Enter your network interface')
