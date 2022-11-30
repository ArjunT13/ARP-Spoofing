# ARP-Spoofing

An ARP spoofing, also known as ARP poisoning, is a cyber attack that allows attackers to intercept communication between network devices.
In this attack, a malicious actor sends falsified ARP (Address Resolution Protocol) messages over a local area network.
Hackers can also use ARP spoofing to alter or block all traffic between devices on the network.
The hacker can intercept and monitor data as it flows between two devices.

# How to place ARP Spoof Attack

The attacker uses the ARP spoofing tool to scan for the IP and MAC addresses of hosts in the target’s subnet.

The attacker chooses its target and begins sending ARP response to the gateway saying that "I have the victim's IP address" and also to the victim saying that "I have the gateway's IP address".

As other hosts on the LAN cache the spoofed ARP packets, data that those hosts send to the victim will go to the attacker instead. From here, the attacker can steal data or launch a more sophisticated follow-up attack.


# How to detect ARP Spoof Attack

A passive monitoring or scanning is performed to sniff the packets in the network after receiving one ARP Packet. Once an ARP packet is received, we analyze two components: <b>The source MAC address </b> (that can be spoofed). <b>The real MAC address of the sender </b> (we can easily get it by initiating an ARP request of the source IP address).

And then, we compare the two. If they are not the same, then we are definitely under an ARP spoof attack

# Results of ARP Spoof Attack Detection (Using WireShark)
