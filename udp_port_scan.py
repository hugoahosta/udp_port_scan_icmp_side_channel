#! /usr/bin/env python
from scapy.all import *
from time import perf_counter, sleep

PORT_SCAN_FREQUENCY = 0.02
PROBE_WAITING_TIME = 0.01

MIN_PORT = 23290
MAX_PORT = 23489
BATCH_SIZE = 50

L2_SOCKET = conf.L2socket(iface='vboxnet0')
PROBING_PACKET = Ether() / IP(dst='192.168.56.101') / UDP(sport=3333, dport=0) / 'Probing for answer'
PROBING_PACKET_RAW = raw(PROBING_PACKET)

NO_OPEN_PORT = -1

def scan_for_open_ports(candidate_port_range_start, range_size):
	destination_ports = [port for port in range(candidate_port_range_start, candidate_port_range_start + range_size)] * int(BATCH_SIZE / range_size)
	padding_port_scans = BATCH_SIZE - len(destination_ports)
	destination_ports += [port for port in range(candidate_port_range_start, candidate_port_range_start + padding_port_scans)]

	packets = [Ether() / IP(src='192.168.56.102', dst='192.168.56.101') / UDP(sport=3333, dport=destination_port) / 'It works!' for destination_port in destination_ports]
	raw_packets = [raw(packet) for packet in packets]

	start_time = perf_counter()
	for raw_packet in raw_packets:
		L2_SOCKET.send(raw_packet)
	answered, unanswered = L2_SOCKET.sr(PROBING_PACKET, timeout=PROBE_WAITING_TIME)
	stop_time = perf_counter()
	sleep(PORT_SCAN_FREQUENCY - (stop_time - start_time))

	if len(answered) > 0:
		return True
	elif len(unanswered) > 0:
		return False
	else:
		raise 'No answered and unanswered datagrams';

def search_open_port(candidate_port_range_start, range_size):
	found = False
	range_size = int(range_size / 2)

	found = scan_for_open_ports(candidate_port_range_start, range_size)
	if found and range_size == 1:
		return candidate_port_range_start
	elif found:
		return search_open_port(candidate_port_range_start, range_size)
	elif not found:
		found = scan_for_open_ports(candidate_port_range_start + range_size, range_size)
		if found and range_size == 1:
			return candidate_port_range_start + range_size
		elif found:
			return search_open_port(candidate_port_range_start + range_size, range_size)
	return NO_OPEN_PORT

def scan_port_range(port_range_start, port_range_end):
	for scanned_port_range_start in range(port_range_start, port_range_end + 1, BATCH_SIZE):
		open_port_in_range = scan_for_open_ports(scanned_port_range_start, BATCH_SIZE)

		if open_port_in_range:
			open_port = search_open_port(scanned_port_range_start, BATCH_SIZE)
			if open_port != NO_OPEN_PORT:
				return open_port

	return NO_OPEN_PORT

if __name__ == '__main__':
	open_port = scan_port_range(MIN_PORT, MAX_PORT)
	if open_port != NO_OPEN_PORT:
		print(f'Found open port {open_port}')
	else:
		print('No open port found')
