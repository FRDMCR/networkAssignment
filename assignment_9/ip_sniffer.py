import os
import socket
import argparse
import struct

ETH_P_ALL = 0x0003
ETH_SIZE = 14

def make_ethernet_header(raw_data):
	ether = struct.unpack('!6B6BH', raw_data)
	# check IP packet
	if ether[12]  == 2048 :
		return {'dst':'%02x:%02x:%02x:%02x:%02x:%02x' % ether[:6],
		'src':'%02x:%02x:%02x:%02x:%02x:%02x' % ether[6:12],
		'ether_type':ether[12]}
	else :
		return 0

def make_ip_header(raw_data) :
	ip = struct.unpack('!BBHHHBBH4B4B', raw_data[:20])  # exclude option 
	return {'version':ip[0]>>4,    # version 4bits
	'header_length':ip[0]&0b00001111,  # HL 4bits
	'tos':ip[1],
	'total_length':ip[2],
	'id':ip[3],
	'flag':(ip[4] >> 13),    # flags 3bits
	'offset':(ip[4] & 0b0001111111111111),  # offset 13bits
	'ttl':ip[5],
	'protocol':ip[6],
	'checksum':ip[7],
	'src':'%d.%d.%d.%d' % ip[8:12],
	'dst':'%d.%d.%d.%d' % ip[12:]}

def dumpcode(buf):
	print("%7s"% "offset ", end='')

	for i in range(0, 16):
		print("%02x " % i, end='')

		if not (i%16-7):
			print("- ", end='')

	print("")

	for i in range(0, len(buf)):
		if not i%16:
			print("0x%04x" % i, end= ' ')

		print("%02x" % buf[i], end= ' ')
		
		if not (i % 16 - 7):
			print("- ", end='')

		if not (i % 16 - 15):
			print(" ")

	print("")

def sniffing(nic):
	#if os.name == 'nt':
	#	address_familiy = socket.AF_INET
	#	protocol_type = socket.IPPROTO_IP
	#else:
	address_familiy = socket.AF_PACKET
	protocol_type = socket.ntohs(ETH_P_ALL)

	with socket.socket(address_familiy, socket.SOCK_RAW, protocol_type) as sniffe_sock:
		sniffe_sock.bind((nic, 0))

		#if os.name == 'nt':
		#	sniffe_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
		#	sniffe_sock.ioctl(socket.SIO_RCVALL,socket.RCVALL_ON)

		while(1) :
			data, _ = sniffe_sock.recvfrom(65535)

			ethernet_header = make_ethernet_header(data[:ETH_SIZE])
			if ethernet_header == 0 :   # not IP packet
				pass
			else :      # IP packet
				print("Ethernet Header")
				for item in ethernet_header.items():
					print('[{0}] : {1}'.format(item[0], item[1]))

				print("")

				ip_size = int(data[ETH_SIZE] >> 4) * 5      # HL * 5 (byte)
				ip_header = make_ip_header(data[ETH_SIZE:ETH_SIZE+ip_size])
				print("IP Header")
				for item in ip_header.items():
					print('[{0}] : {1}'.format(item[0], item[1]))

				print("")
                
			print("Raw Data")
			dumpcode(data)

			print("")

			#if os.name == 'nt':
			#	sniffe_sock.ioctl(socket.SIO_RCVALL,socket.RCVALL_OFF)

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description='This is a simpe packet sniffer')
	parser.add_argument('-i', type=str, required=True, metavar='NIC name', help='NIC name')
	args = parser.parse_args()

	sniffing(args.i)
