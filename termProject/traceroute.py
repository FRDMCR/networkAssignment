import argparse
import socket
import struct
import packet
import sys
import time
import icmp_sniffer

ETH_SIZE = 14
IP_SIZE = 20            # exclude option size 
ICMP_SIZE = 8           # exclude data size
UDP_SIZE = 8            # exclude data size
SRC_PORT = 10000
DST_PORT = 53
DATA = 'a'
TIME_EXCEEDED = 11   # Type
ECHO_REPLY = 0
DESTINATION_UNREACHABLE = 3    

def traceroute (dst_addr, packet_size , proto, maximum_hop, timeout, dst_port) :
    try :                                               # domain to ip address
        dst_ip = socket.gethostbyname(dst_addr)
        dst_host = socket.gethostbyaddr(dst_addr)[0]
    except socket.gaierror :
        print("Incorrect address")
        sys.exit()

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as echo_sock :
        echo_sock.bind(('', SRC_PORT))
        
        sniff_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sniff_sock.bind(('', SRC_PORT))

        sniff_sock.settimeout(float(timeout))           # set timeout

        if proto == socket.IPPROTO_ICMP :               # in order to make data
            data_size = packet_size - IP_SIZE - ICMP_SIZE
        elif proto == socket.IPPROTO_UDP :
            data_size = packet_size - IP_SIZE - UDP_SIZE

        ip_raw = packet.Ip(proto, dst_ip, maximum_hop)
        icmp_raw = packet.Icmp(DATA * data_size)
        udp_raw = packet.Udp(SRC_PORT, dst_port, DATA * data_size)

        print(f"traceroute to {dst_host} ({dst_ip}), {maximum_hop} hops max, {packet_size} byte packets")
    
        success = 0                                     # If the destination is found, change it to 1
        for hop_cnt in range(1, maximum_hop+1) :        # increase the number of hops(ttl) and seqeunce number
            ip_raw.set_ttl(hop_cnt)
            if proto == socket.IPPROTO_ICMP :
                icmp_raw.set_seq(hop_cnt)
                echo_raw = ip_raw.make_ip_field() + icmp_raw.make_icmp_field()
            elif proto == socket.IPPROTO_UDP :
                echo_raw = ip_raw.make_ip_field() + udp_raw.make_udp_field()

            rtt = []                       #  round trip time
            limit = 3                                   #  limited to find route or host
            for j in range(3) :
                echo_sock.sendto(echo_raw, (dst_ip , dst_port))

                try :
                    start = time.time()
                    res_data, res_addr = sniff_sock.recvfrom(65535)
                    end = time.time()
                    rtt.insert(j, str((end - start) * 1000)[0:5] + ' ms')   # ms

                except socket.timeout :                # timeout
                    rtt.insert(j, '*')
                    limit -= 1
                    continue
                
                try :
                    hop_name = socket.gethostbyaddr(res_addr[0])[0]
                    hop_ip  = res_addr[0]

                except socket.gaierror :               # not found domain
                    hop_name = '_gateway'
                    hop_ip  = res_addr[0]
                    pass

                except socket.herror :                 # not found domain
                    hop_name = '_gateway'
                    hop_ip  = res_addr[0]
                    pass

                sniff_icmp = icmp_sniffer.Sniffing(res_data)
                
                # TIME_EXCEEDED #
                if sniff_icmp.get_icmp_type() == TIME_EXCEEDED and sniff_icmp.get_icmp_code() == 0 :
                    continue

                # ECHO_REPLY #
                elif sniff_icmp.get_icmp_type() == ECHO_REPLY and sniff_icmp.get_icmp_code() == 0 :
                    if sniff_icmp.get_return_icmp_id() ==  icmp_raw.get_id() and sniff_icmp.get_return_icmp_data() == DATA * data_size :
                        success = 1
                        continue
                    else :                          # not my packet
                        rtt.insert(j, '*')
                        limit -= 1
                        continue

                # DESTINATION_UNREACHABLE - Port unreachable #
                elif sniff_icmp.get_icmp_type() == DESTINATION_UNREACHABLE and sniff_icmp.get_icmp_code() == 0 :
                    if sniff_icmp.get_return_ip_id() == ip_raw.get_id() and sniff_icmp.get_udp_dst_prot == dst_port :
                        success = 1
                        continue
                    else :                          # not my packet
                        rtt.insert(j, '*')
                        limit -= 1
                        continue

            if limit == 0 :
                print("%2d  " % hop_cnt + "* * *")
            else :
                print("%2d  " % hop_cnt + f"{hop_name}  ({hop_ip})  {rtt[0]}  {rtt[1]}  {rtt[2]}")

            if success == 1 :                      # succeed to finding destination
                break

        sniff_sock.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='traceroute address(destination IP or Domain) size [-I or -U] [-c] [-t] [-p]')
    parser.add_argument('address', type=str, help = 'destination IP or Domain')
    parser.add_argument('size', type=int, help = 'packet size excluding ip')

    proto_group = parser.add_mutually_exclusive_group()
    proto_group.add_argument('-I', nargs = '?', const = socket.IPPROTO_ICMP, default = socket.IPPROTO_ICMP, help = 'using ICMP')
    proto_group.add_argument('-U', nargs = '?', const = socket.IPPROTO_UDP, help = 'using UDP')

    parser.add_argument('-c', type=int, required = False, default = 30, help = 'maximum hops')
    parser.add_argument('-t', type=int, required = False, default = 5 ,help = 'time out')
    parser.add_argument('-p', type=int, required = False, default = DST_PORT ,help = 'destination dst_port')
    
    args = parser.parse_args()

    if args.U :
        traceroute(args.address, args.size, args.U, args.c, args.t, args.p)
    else :
        traceroute(args.address, args.size, args.I, args.c, args.t, args.p)
