# -*- coding: utf-8 -*-

from scapy.all import *
import time

lastTime = time.time()


def arp_display(pkt):
	global lastTime;

	if pkt[ARP].op == 1: #who-has (request)
		if pkt[ARP].hwsrc == '78:e1:03:25:c5:50': # Dolce Gusto
			if (time.time()-lastTime) > 2:
				print "Desperta ferro!"
				lastTime = time.time()
		#else:
		#	print "ARP Probe from unknown device: " + pkt[ARP].hwsrc

print sniff(iface='wlx00c0ca975f6e', prn=arp_display, filter="arp", store=0, count=0)
