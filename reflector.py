#!/usr/bin/env python

from ctypes import *
from winpcapy import *
import time
import sys
import string
import platform
import impacket
from impacket import ImpactDecoder
from impacket import ImpactPacket
import array

def ip_mac_to_array(ipmac, is_ip):
	if is_ip:
		return array.array('B', [int(x) for x in ipmac.split(".")])
	return array.array('B', [int(x, 16) for x in ipmac.split(":")])

OUR_IP = "203.0.113.10"
OUR_IP_ARRAY = ip_mac_to_array( OUR_IP, 1 )

REFLECT_IP = "203.0.113.1"
REFLECT_IP_ARRAY = ip_mac_to_array( REFLECT_IP, 1 )

REFLECT_PORT = 445
REFLECT_PORT_TO = 1445

OUR_MAC = "0E:CD:FE:0D:38:DE"
OUR_MAC_ARRAY = ip_mac_to_array( OUR_MAC, 0 )
BROADCAST_MAC = "FF:FF:FF:FF:FF:FF"
BROADCAST_MAC_ARRAY = ip_mac_to_array( BROADCAST_MAC, 0 )

REFLECT_MAP = { 445: 1445, 137: 1137, 138: 1138, 139: 1139 }
REFLECT_MAP_TO = dict( zip( REFLECT_MAP.values(), REFLECT_MAP.keys() ) )

reply = 0

if platform.python_version()[0] == "3":
	raw_input=input

header = POINTER(pcap_pkthdr)()
pkt_data = POINTER(c_ubyte)()
alldevs = POINTER(pcap_if_t)()
errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
bpf = bpf_program()

## Retrieve the device list
if (pcap_findalldevs(byref(alldevs), errbuf) == -1):
	print ("Error in pcap_findalldevs: %s\n" % errbuf.value)
	sys.exit(1)
## Print the list
i=0
try:
	d=alldevs.contents
except:
	print ("Error in pcap_findalldevs: %s" % errbuf.value)
	print ("Maybe you need admin privilege?\n")
	sys.exit(1)
while d:
	i=i+1
	print("%d. %s" % (i, d.name))
	if (d.description):
		print (" (%s)\n" % (d.description))
	else:
		print (" (No description available)\n")
	if d.next:
		d=d.next.contents
	else:
		d=False

if (i==0):
	print ("\nNo interfaces found! Make sure WinPcap is installed.\n")
	sys.exit(-1)
print ("Enter the interface number (1-%d):" % (i))
#inum= raw_input('--> ')
inum = "1"
if inum in string.digits:
    inum=int(inum)
else:
    inum=0
if ((inum < 1) | (inum > i)):
    print ("\nInterface number out of range.\n")
    ## Free the device list
    pcap_freealldevs(alldevs)
    sys.exit(-1)
## Jump to the selected adapter
d=alldevs
for i in range(0,inum-1):
    d=d.contents.next
## Open the device
## Open the adapter
d=d.contents

adhandle = pcap_open_live(d.name,65536,1,1,errbuf)
if (adhandle == None):
    print("\nUnable to open the adapter. %s is not supported by Pcap-WinPcap\n" % d.contents.name)
    ## Free the device list
    pcap_freealldevs(alldevs)
    sys.exit(-1)
print("\nlistening on %s...\n" % (d.description))

pcap_compile(adhandle, bpf, "ether host %s or ether broadcast" % OUR_MAC, 1, 0)
pcap_setfilter(adhandle, bpf)

## At this point, we don't need any more the device list. Free it
pcap_freealldevs(alldevs)

ethdecoder = ImpactDecoder.EthDecoder()

def build_ethernet_reply(eth, proto):
	reply = ImpactPacket.Ethernet()
	reply.set_ether_dhost( eth.get_ether_shost() )
	reply.set_ether_shost( OUR_MAC_ARRAY )
	reply.set_ether_type( proto )
	return reply

def build_ip_reply(ip, proto):
	reply = ImpactPacket.IP()
	reply.set_ip_dst( ip.get_ip_src() )
	reply.set_ip_src( OUR_IP )
	reply.set_ip_p( proto )
	return reply

def build_tcp_reply(tcp):
	reply = ImpactPacket.TCP()
	reply.set_th_sport( tcp.get_th_dport() )
	reply.set_th_dport( tcp.get_th_sport() )

def handle_arp(pcap, wire_packet):
	arp = wire_packet.child()
	if arp.get_op_name(arp.get_ar_op()) == 'REQUEST' and arp.as_pro(arp.get_ar_tpa()) == OUR_IP:
		reply = build_ethernet_reply( wire_packet, ImpactPacket.ARP.ethertype )

		reply_arp = ImpactPacket.ARP()
		reply_arp.set_ar_op(2) # reply
		reply_arp.set_ar_hrd(1) # ethernet
		reply_arp.set_ar_pro( ImpactPacket.IP.ethertype )
		reply_arp.set_ar_hln(6)
		reply_arp.set_ar_pln(4)
		reply_arp.set_ar_tpa( arp.get_ar_spa() )
		reply_arp.set_ar_spa( arp.get_ar_tpa() )
		reply_arp.set_ar_tha( arp.get_ar_sha() )
		reply_arp.set_ar_sha( OUR_MAC_ARRAY )

		reply.contains(reply_arp)
		reply_str = reply.get_packet()
		pcap_sendpacket(pcap, cast(reply_str, POINTER(u_char)), len(reply_str))
# Why doesn't this work for ARP when it works for everything else?
#		pcap_sendpacket(pcap, cast(reply.get_packet(), POINTER(u_char)), reply.get_size())

def handle_icmp(pcap, wire_packet, ip):
	icmp = ip.child()
	if icmp.get_icmp_type() == ImpactPacket.ICMP.ICMP_ECHO:
		reply = build_ethernet_reply( wire_packet, ImpactPacket.IP.ethertype )
		ip_reply = build_ip_reply( ip, ImpactPacket.ICMP.protocol )

		icmp_reply = ImpactPacket.ICMP()
		icmp_reply.set_icmp_type( ImpactPacket.ICMP.ICMP_ECHOREPLY )
		icmp_reply.set_icmp_seq( icmp.get_icmp_seq() )
		icmp_reply.set_icmp_id( icmp.get_icmp_id() )
		icmp_reply.contains( ImpactPacket.Data( icmp.get_data_as_string() ) )

		ip_reply.contains( icmp_reply )
		reply.contains( ip_reply )

		pcap_sendpacket(pcap, cast(reply.get_packet(), POINTER(u_char)), reply.get_size())

def handle_tcp2(pcap, wire_packet, ip):
	tcp = ip.child()
	if (	tcp.get_th_dport() == REFLECT_PORT
		 or tcp.get_th_sport() == REFLECT_PORT_TO
	):
		reply = build_ethernet_reply( wire_packet, ImpactPacket.IP.ethertype )
		ip_reply = build_ip_reply( ip, ImpactPacket.TCP.protocol )

		if tcp.get_th_dport() == REFLECT_PORT:
			tcp.set_th_dport( REFLECT_PORT_TO )
		else:
			tcp.set_th_sport( REFLECT_PORT )

		ip_reply.contains( tcp )
		reply.contains( ip_reply )
		pcap_sendpacket(pcap, cast(reply.get_packet(), POINTER(u_char)), reply.get_size())

def handle_tcp(pcap, wire_packet, ip):
	tcp = ip.child()
	if (	REFLECT_MAP.has_key(tcp.get_th_dport())
		 or REFLECT_MAP_TO.has_key(tcp.get_th_sport())
	):
		global reply
		if not reply :
			reply = build_ethernet_reply( wire_packet, ImpactPacket.IP.ethertype )

		ip_reply = build_ip_reply( ip, ImpactPacket.TCP.protocol )

		if REFLECT_MAP.has_key(tcp.get_th_dport()):
			tcp.set_th_dport( REFLECT_PORT_TO )
		else:
			tcp.set_th_sport( REFLECT_PORT )

		ip_reply.contains( tcp )
		reply.contains( ip_reply )
		pcap_sendpacket(pcap, cast(reply.get_packet(), POINTER(u_char)), reply.get_size())


## Retrieve the packets
res = 1
while(res >= 0):
	res=pcap_next_ex( adhandle, byref(header), byref(pkt_data))
	if(res == 0):
		# Timeout elapsed
		continue

	packet = ethdecoder.decode(string_at(pkt_data, header.contents.len))
	#if packet.get_ether_dhost() != OUR_MAC_ARRAY and packet.get_ether_dhost() != BROADCAST_MAC_ARRAY:
	#	continue

	if packet.get_ether_type() == ImpactPacket.IP.ethertype:
		ip = packet.child()
		if ( ip.get_ip_dst() != OUR_IP ): continue
		if ip.get_ip_p() == ImpactPacket.TCP.protocol:
			handle_tcp(adhandle, packet, ip)
		if ip.get_ip_p() == ImpactPacket.ICMP.protocol:
			handle_icmp(adhandle, packet, ip)

	elif packet.get_ether_type() == ImpactPacket.ARP.ethertype:
		handle_arp(adhandle, packet)

if(res == -1):
	print("Error reading the packets: %s\n", pcap_geterr(adhandle));
	sys.exit(-1)
pcap_close(adhandle)
