## client.py

import socket
import threading
import argparse
import time

## 소켓 송신 함수 ##
def send_to_server(s):       
    while True:
        client_str = input()     ## block
        s.sendall(client_str.encode())


## 소켓 수신 함수 ##
def recv_from_client(s, host, port):
    while True:
        resp = s.recv(1024)       ## block
        print("From : ", host, ':', port, ', ', resp.decode())


def run(host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))

        ## 흐름을 송신 처리 스레드와 수신 처리 스레드로 분리
        recv_thread = threading.Thread(target=recv_from_client, args=(s, host, port))
        send_thread = threading.Thread(target=send_to_server, args=(s, ))
        
        recv_thread.start()
        send_thread.start()

        while True :    ## with 구문 탈출 방지 & main이 끝나지 않도록 하기 위해
            time.sleep(1)   ## 텀을 줘서 무한 루프의 부담을 줄임

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Echo client -p port -i host")
    parser.add_argument('-p', help="port_number", required=True)
    parser.add_argument('-i', help="host_name", required=True)
    
    args = parser.parse_args()
    
    run(host=args.i, port=int(args.p))