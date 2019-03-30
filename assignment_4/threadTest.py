import threading
import time

def myThread(index):
    for i in range(index): 
        print("My thread")
        time.sleep(2)

t = threading.Thread(target = myThread, args=(3,))

t.start()

for i in range(3):
    print("main")
    time.sleep(1)

print("---end---")