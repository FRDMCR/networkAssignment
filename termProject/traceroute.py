import argparse
import socket
import struct
import header
import sys

def traceroute (dst_addr, proto, hop, timeout) :

    try :   # domain to ip address
        dst_ip = socket.gethostbyname(dst_addr)
        dst_host = socket.gethostbyaddr(dst_addr)[0]
    except socket.gaierror :
        print("Incorrect address")
        sys.exit()
    
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='traceroute -d [-I or -U] [-h] [-t]')
    parser.add_argument('-d', type=str, required = True, help = 'destination IP or Domain')

    proto_group = parser.add_mutually_exclusive_group()
    proto_group.add_argument('-I', nargs = '?', const = socket.IPPROTO_ICMP, default = socket.IPPROTO_ICMP, help = 'using ICMP')
    proto_group.add_argument('-U', nargs = '?', const = socket.IPPROTO_UDP, help = 'using UDP')

    parser.add_argument('-h', required = False, default = 30, help = 'maximum hops')
    parser.add_argument('-t', required = False, default = 5 ,help = 'time out')
    args = parser.parse_args()

    if args.U :
        traceroute(args.d, args.U, args.h, args.t)
    else :
        traceroute(args.d, args.I, args.h, args.t)