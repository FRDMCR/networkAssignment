import argparse
import socket
import struct

def make_ip_header(destination) :
    ip_header = {'version': 4,
	'header_length': 5,
	'tos': 0,
	'total_length':30,
	'id': 0,
	'flag/offset': 0,
	'ttl': 128,
	'protocol': 1,
	'checksum': 0,
	'src': list(map(int, socket.gethostbyname(socket.gethostname().split('.')))),
	'dst': list(map(int, destination.split('.'))) }

    ip_raw = struct.pack('!BBHHHBBH4B4B',
    int('0x' + str(ip_header['version']) + str(ip_header['header_length']), 16),
    ip_header['tos'],
    ip_header['total_length'],
    ip_header['id'],
    ip_header['flag/offset'],
    ip_header['ttl'],
    ip_header['protocol'],
    ip_header['checksum'],
    ip_header['src'][0],ip_header['src'][1],ip_header['src'][2],ip_header['src'][3],
    ip_header['dst'][0],ip_header['dst'][1],ip_header['dst'][2],ip_header['dst'][3])

def make_icmp_header() :
    icmp_header = { 'type' : 8,
    'code' : 0,
    'checksum' : 0,
    'id' : 0,
    'sequence_number' : 0,
    'data' : 'aa'}

    icmp_raw = struct.pack('!BBHHH2s',
    icmp_header['type'],
    icmp_header['code'],
    icmp_header['checksum'],
    icmp_header['id'],
    icmp_header['sequence_number'],
    icmp_header['data'].encode())

def echo_request(des_ip) :

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as request_sock :
        request_sock.bind(('', 0))

        try :   # domain to ip address
            des_ip = socket.gethostbyname(des_ip)

        except socket.gaierror :
            print("Incorrect domain name")
    



if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This is ICMP echo request packet')
    parser.add_argument('-d', type=str, required = True, help = 'destination IP or Domain')
    args = parser.parse_args()

    echo_request(args.i)

