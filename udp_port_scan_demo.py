#! /usr/bin/env python
from scapy.all import *

PORT_SCAN_FREQUENCY=0.02

MIN_PORT = 23440
MAX_PORT = 23489
BATCH_SIZE = 50

l2_socket = conf.L2socket(iface='vboxnet0')
probing_packet = Ether() / IP(dst='192.168.56.101') / UDP(sport=3333, dport=0) / 'Probing for answer'
probin_packet_raw = raw(probing_packet)

for scanned_port_range_start in range(MIN_PORT, MAX_PORT + 1, BATCH_SIZE):
	destination_ports = [port for port in range(scanned_port_range_start, scanned_port_range_start + BATCH_SIZE)]
	packets = [Ether() / IP(src='192.168.56.102', dst='192.168.56.101') / UDP(sport=3333, dport=destination_port) / 'It works!' for destination_port in destination_ports]
	raw_packets = [raw(packet) for packet in packets]
	for raw_packet in raw_packets:
		l2_socket.send(raw_packet)
	answered, unanswered = l2_socket.sr(probing_packet, timeout=PORT_SCAN_FREQUENCY)
	if len(answered) > 0:
		print('Received an answer --> at least one port in the range is open')
	elif len(unanswered) > 0:
		print('Received no answer --> no port in the range is open')
