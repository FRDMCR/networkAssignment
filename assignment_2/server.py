## sever.py

import socket
import argparse

def run_server(port=4000):
    host = ''   ## 127.0.0.1 Loop back

    with socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen(1)     ## max 1 client

        conn, addr = s.accept()
        msg = conn.recv(1024)
        
        rMsg = reverseMsg(msg.decode()) ## msg is a binary data, so we need to decode it
        print(rMsg)

        conn.sendall(rMsg.encode())
        conn.close()

## 입력한 문자열을 반대로 뒤집어 주는 함수
def reverseMsg(str):
    size = len(str)
    reverseStr=''
    for i in range(size-1, -1, -1):
        reverseStr+=str[i]
    
    return reverseStr

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Echo server -p port")
    parser.add_argument('-p', help="port_number", required=True)

    args = parser.parse_args()
    run_server(port=int(args.p))       