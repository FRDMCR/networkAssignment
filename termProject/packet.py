import socket
import struct

#calculate icmp & udp packets's checksum
def checksum (msg) :
    if len(msg) % 2 != 0 :  # if msg's byte length is odd number
        msg = msg + b'0'  # make to even number

    checksum = 0
    for x in struct.unpack('!' + str(len(msg)//2) + 'H', msg) :  # slice to 2 byte
        checksum += x

        if checksum > 0xffff :  
            checksum = (checksum & 0xffff) + (checksum >> 16)

    checksum = ~checksum & 0xffff

    return struct.pack('!H', checksum)
    
# make IP packet field and return raw data
class Ip() :
    def __init__(self, protocol, dst, ttl) :
        self.version = 4,
        self.header_length = 5,
        self.tos = 0,
        self.total_length = 0,
        self.id = 0,
        self.flag_offset = 0,
        self.ttl = ttl,
        self.protocol = protocol,
        self.checksum = 0,
        self.src = 0,
        self.dst = list(map(int, dst.split('.')))


    def make_ip_field(self) :
        raw = struct.pack('!BBHHHBBHIB',
        int('0x' + str(self.version) + str(self.header_length), 16),
        self.tos,
        self.total_length,
        self.id,
        self.flag_offset,
        self.ttl,
        self.protocol,
        self.checksum,
        self.src,
        self.dst[0], self.dst[1], self.dst[2], self.dst[3])

        return raw

# make ICMP packet field and return raw data
class Icmp() :
    def __init__(self, data) :
        self.type = 8,
        self.code = 0,
        self.checksum = 0,
        self.id = 0,
        self.sequence_num = 0,
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

# make UDP packet field and return raw data
class Udp() :
    def __init__(self, src_port, dst_port, data) :
        self.src_port = int(src_port),
        self.dst_port = int(dst_port),
        self.length = 8 + len(data),
        self.checksum = 0,
        self.data = data

    def make_udp_field(self) :
        raw = struct.pack('!4H' + str(len(self.data)) + 's',
        self.src_port,
        self.dst_port,
        self.length,
        self.checksum,
        self.data.encode())

        return raw[:3] + checksum(raw) + raw[4:]