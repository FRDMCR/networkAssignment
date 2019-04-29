## server.py

import socket
import threading
import argparse
import time

## 소켓 송신 함수 ##
def send_to_client(conn):
    while True:
        try :
            server_str = input()   ## block
            conn.sendall(server_str.encode())
        except KeyboardInterrupt :      ## conn.close()
            break
    
## 소켓 수신 함수 ##
def recv_from_server(conn, host, port):
    while True:
        msg = conn.recv(1024)       ## block
        print("From : ", host, ':', port, ', ', msg.decode())


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Thread server -p port")
    parser.add_argument('-p', help = "port_number", required = True)

    args = parser.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(('', int(args.p)))
        server.listen(5)
        conn, addr = server.accept()
        
        print("Connected to : ", addr[0], ' : ', addr[1])

        ## 흐름을 송신 처리 스레드와 수신 처리 스레드로 분리
        recv_thread = threading.Thread(target=recv_from_server, args=(conn, addr[0], addr[1]))
        send_thread = threading.Thread(target=send_to_client, args=(conn, ))
        
        recv_thread.start()
        send_thread.start()

        while True :    ## with 구문 탈출 방지 & main이 끝나지 않도록 하기 위해
            time.sleep(1)   ## 텀을 줘서 무한 루프의 부담을 줄임
