## server.py

import socket
import threading
import argparse

def socket_handler(conn):
    msg = conn.recv(1024)
    rMsg = reverseMsg(msg.decode()) 
    print("Connected ")

    conn.sendall(rMsg.encode())
    conn.close()
    print("Closed ")

## 입력한 문자열을 반대로 뒤집어 주는 함수
def reverseMsg(str):
    size = len(str)
    reverseStr=''
    for i in range(size-1, -1, -1):
        reverseStr+=str[i]
    
    return reverseStr

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Thread server -p port")
    parser.add_argument('-p', help = "port_number", required = True)

    args = parser.parse_args()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('', int(args.p)))
    server.listen(5)
    
    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=socket_handler, args=(conn, ))
        t.start()

    server.close()