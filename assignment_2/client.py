## client.py

import socket
import argparse

def run(host, port, strList):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        msg = reverseMsg(strList)
        s.sendall(msg.encode())

        resp = s.recv(1024)
        print(resp.decode())

## 입력한 문자열을 반대로 뒤집어 주는 함수
def reverseMsg(strList):
    str = " ".join(strList)     ## 리스트 요소 사이에 공백을 넣어 스트링으로 변환
    size = len(str)
    reverseStr=''
    for i in range(size-1, -1, -1):
        reverseStr+=str[i]
    
    return reverseStr

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Echo client -p port -i host -s string")
    parser.add_argument('-p', help="port_number", required=True)
    parser.add_argument('-i', help="host_name", required=True)
    parser.add_argument('-s', help="input_string", nargs='+', required=True)

    args = parser.parse_args()
    run(host=args.i, port=int(args.p), strList=args.s)