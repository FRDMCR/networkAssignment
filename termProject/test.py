import time
import struct
import sniffer
import socket

test = struct.unpack('!B', b'\01')
if int(test[0]) == socket.IPPROTO_ICMP :
    print('OK')