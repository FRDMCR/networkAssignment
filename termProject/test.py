import argparse
import socket
import struct
import packet
import sys

ETH_LENGTH = 14
SRC_PORT = 10000
DST_PORT = 13000
DATA = 'cheeseburger'

udp_header = packet.Udp(SRC_PORT, DST_PORT, DATA)
print(udp_header.length)
print(udp_header.make_udp_field()[1])