import time

tu = 1,2

start = time.time()
time.sleep(1)
end = time.time()
difference = end - start

print((start - end))
print(tu[0])

rtt = [] 
for j in range(3) :
    rtt.insert(j, 1)   # ms
    print(j)