import time
import struct
import socket

test = struct.unpack('!s', b'a')
if test[0].decode() == 'a' :
    print('OK')