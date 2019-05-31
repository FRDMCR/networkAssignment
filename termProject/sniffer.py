import os
import socket
import argparse
import struct
import packet

ETH_SIZE = 14

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

def parse_icmp_header(data) :
    headerlist = struct.unpack('!BBHHH', str(len(data)-8) + 's', data)
    return {'type' : headerlist[0],
    'code' : headerlist[1],
    'checksum' : headerlist[2],
    'id' : headerlist[3],
    'sequence_num' : headerlist[4],
    'data' : headerlist[5:]}    

class Sniffing() :
    
    def init(self, data) :
        self.ip_size = int(data[ETH_SIZE] >> 4) * 5                   # HL * 5 (byte)
        self.ip_header = parse_ip_header(data[ETH_SIZE : ETH_SIZE+20])  # exclude option
        self.icmp_header = parse_icmp_header(data[ETH_SIZE+self.ip_size :])

    def get_ip_id(self) :
        return int(self.ip_header['id'])

    def get_ip_dst(self) :
        return self.ip_header['dst']

    def get_icmp_id(self) :
        return int(self.icmp_header['id'])

    def get_icmp_type(self) :
        return int(self.icmp_header['type'])

    def get_icmp_code(self) :
        return int(self.icmp_header['code'])

    def get_icmp_data(self) :
        return self.icmp_header['data']