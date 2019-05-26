import argparse
import socket
import struct
import packet
import sys

ETH_LENGTH = 14
SRC_PORT = 10000
DST_PORT = 13000
DATA = 'cheeseburger'

def traceroute (dst_addr, proto, maximum_hop, timeout) :
    try :   # domain to ip address
        dst_ip = socket.gethostbyname(dst_addr)
        dst_host = socket.gethostbyaddr(dst_addr)[0]
    except socket.gaierror :
        print("Incorrect address")
        sys.exit()

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as echo_sock :
        echo_sock.bind(('', SRC_PORT))
        
        ip_header = packet.Ip(proto, dst_ip, maximum_hop)
        ip_raw = ip_header.make_ip_field()

        if proto == socket.IPPROTO_ICMP :   # make icmp raw packet
            icmp_header = packet.Icmp(DATA)
            icmp_raw = icmp_header.make_icmp_field()
            echo_raw = ip_raw + icmp_raw
        elif proto == socket.IPPROTO_UDP :      # make udp raw packet
            udp_header = packet.Udp(SRC_PORT, DST_PORT, DATA)
            udp_raw = udp_header.make_udp_field()
            echo_raw = ip_raw + udp_raw

        print(f"traceroute to {dst_host} ({dst_ip}), {maximum_hop} hops max, {len(echo_raw)+ETH_LENGTH} byte packets")
        
        for hop_cnt in range(1, maximum_hop+1) :
            ip_header.set_ttl(hop_cnt)
            if proto == socket.IPPROTO_ICMP :
                echo_raw = ip_header.make_ip_field + icmp_raw
            elif proto == socket.IPPROTO_UDP :
                echo_raw = ip_header.make_ip_field + udp_raw

            #for j in range(3) :
            echo_sock.sendto(echo_raw, (dst_ip , DST_PORT))

        #print("%2d  " % hop_cnt + f"{hop_name}  ({hop_ip})  {rtt[0]}  {rtt[1]}  {rtt[2]}")


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