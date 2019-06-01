import socket
import struct

IP_SIZE = 20            # exclude option size 
ICMP_SIZE = 8           # exclude data size
UDP_SIZE = 8            # exclude data size
TIME_EXCEEDED = 11      # Type
ECHO_REPLY = 0
DESTINATION_UNREACHABLE = 3   

def parse_ip_header(data) :
    headerlist = struct.unpack('!BBHHHBBH4B4B',data)
    return {'version' : headerlist[0]>>4,                 # version 4bits
    'header_length' :headerlist[0]&0b00001111,           # HL 4bits
    'tos': headerlist[1],
    'total_length' :headerlist[2],
    'id' :headerlist[3],
    'flag_offset' : headerlist[4],
    'ttl' : headerlist[5],
    'protocol' : headerlist[6],
    'checksum' : headerlist[7],
    'src' : '%d.%d.%d.%d' % headerlist[8:12],
    'dst' : '%d.%d.%d.%d' % headerlist[12:]}

def parse_icmp_message(data) :
    headerlist = struct.unpack('!BBHI', data)
    return {'type' : headerlist[0],
    'code' : headerlist[1],
    'checksum' : headerlist[2],
    'null' : headerlist[3]}

def parse_icmp_header(data) :
    headerlist = struct.unpack('!BBHHH' + str(len(data) - ICMP_SIZE) + 's', data)
    return {'type' : headerlist[0],
    'code' : headerlist[1],
    'checksum' : headerlist[2],
    'id' : headerlist[3],
    'sequence_num' : headerlist[4],
    'data' : headerlist[5:]}    

def parse_udp_header(data) :
    headerlist = struct.unpack('!4H' + str(len(data) - UDP_SIZE) + 's', data)
    return {'src_port' : headerlist[0],
    'dst_port' : headerlist[1],
    'length' : headerlist[2],
    'checksum' : headerlist[3],
    'data' : headerlist[4:]}

class Sniffing() :
    
    def __init__(self, data) :
        self.ip_size = int(data[0] >> 4) * 5                             # HL * 5 (byte)

        self.ip_header = parse_ip_header(data[0 : IP_SIZE])              # exclude option
        self.icmp_header = parse_icmp_header(data[self.ip_size : ])

        if self.icmp_header['type'] == TIME_EXCEEDED or self.icmp_header['type'] == DESTINATION_UNREACHABLE :
            self.return_ip_header = parse_ip_header(data[self.ip_size + ICMP_SIZE : self.ip_size + ICMP_SIZE + IP_SIZE])
            if self.return_ip_header['protocol'] == socket.IPPROTO_ICMP :
                self.return_icmp_header = parse_icmp_header(data[self.ip_size + ICMP_SIZE + self.ip_size : ])
            elif self.return_ip_header['protocol'] == socket.IPPROTO_UDP :
                self.return_udp_header = parse_udp_header(data[self.ip_size + ICMP_SIZE + self.ip_size : ])
        
        elif self.icmp_header['type'] == ECHO_REPLY :
            pass

    def get_icmp_type(self) :
        return self.icmp_header['type']

    def get_icmp_code(self) :
        return self.icmp_header['code']

    def get_icmp_id(self) :
        return self.icmp_header['id']

    def get_icmp_data(self) :
        return self.icmp_header['data'][0].decode()

    def get_return_ip_id(self) :
        return int(self.return_ip_header['id'])

    def get_return_ip_dst(self) :
        return self.return_ip_header['dst']

    def get_return_icmp_id(self) :
        return int(self.return_icmp_header['id'])

    def get_udp_dst_prot(self) :
        return self.return_udp_header['dst_port']
