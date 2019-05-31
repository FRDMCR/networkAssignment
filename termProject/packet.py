import socket
import struct
from functools import reduce
import random

#calculate icmp & udp packets's checksum
def checksum (header) :
    size = len(header)
    if (size % 2) == 1:
        header += b'\x00'
        size += 1

    size = size // 2
    header = struct.unpack('!' + str(size) + 'H', header)
    sum = reduce(lambda x, y : x+y, header)
    checksum = (sum >> 16) + (sum & 0xffff)
    checksum += checksum >> 16
    checksum = (checksum ^ 0xffff)

    return struct.pack('!H', checksum)
    
# make IP packet field and return raw data
class Ip() :
    def __init__(self, protocol, dst, ttl) :
        self.version = 4
        self.header_length = 5
        self.tos = 0
        self.total_length = 0
        self.id = random.randrange(0,65535)
        self.flag_offset = 0
        self.ttl = ttl
        self.protocol = protocol
        self.checksum = 0
        self.src = [0]
        self.dst = list(map(int, dst.split('.')))


    def make_ip_field(self) :
        raw = struct.pack('!BBHHHBBHI4B',
        int('0x' + str(self.version) + str(self.header_length), 16),
        self.tos,
        self.total_length,
        self.id,
        self.flag_offset,
        self.ttl,
        self.protocol,
        self.checksum,
        self.src[0],
        self.dst[0], self.dst[1], self.dst[2], self.dst[3])

        return raw

    def set_ttl(self, ttl) :
        self.ttl = ttl

    def get_id(self) :
        return self.id

# make ICMP packet field and return raw data
class Icmp() :
    def __init__(self, data) :
        self.type = 8
        self.code = 0
        self.checksum = 0
        self.id = random.randrange(0,65535)
        self.sequence_num = 0
        self.data = data


    def make_icmp_field(self) :
        raw = struct.pack('!BBHHH' + str(len(self.data)) + 's',
        self.type,
        self.code,
        self.checksum,
        self.id,
        self.sequence_num,
        self.data.encode())

        return raw[:2] + checksum(raw) + raw[4:]

    def set_seq(self, seq) :
        self.sequence_num = seq

    def get_id(self) :
        return self.id
        
# make UDP packet field and return raw data
class Udp() :
    def __init__(self, src_port, dst_port, data) :
        self.src_port = int(src_port)
        self.dst_port = int(dst_port)
        self.length = 8 + len(data)
        self.checksum = 0
        self.data = data

    def make_udp_field(self) :
        raw = struct.pack('!4H' + str(len(self.data)) + 's',
        self.src_port,
        self.dst_port,
        self.length,
        self.checksum,
        self.data.encode())

        return raw[:6] + checksum(raw) + raw[8:]