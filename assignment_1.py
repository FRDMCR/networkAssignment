#컴퓨터 네트워크 1주차_quicksort
#컴퓨터공학과
#2014040013 정성진
#Deadline : 2019-03-12

#퀵정렬 함수
def quicksort(xList):
    
    if len(xList) <= 1:
        return xList
    
    smallerList = []
    biggerList = []
    equalList = []

    pivot = xList[len(xList) // 2]
    
    for i in xList:
        if i < pivot:
            smallerList.append(i)
        elif i > pivot:
            biggerList.append(i)
        else:
            equalList.append(i)

    return quicksort(smallerList) + equalList + quicksort(biggerList)

#정수 검사 함수
def isInt(n):
    try:
        int(n)
        return True
    except ValueError:
        return False

import sys

inputList = []
error = "잘못 입력하셨습니다.\n[파일명][-o][A:오름차순 or D:내림차순][-i][정렬할 정수 배열]"

#정수 배열을 입력했는지 검사
for x in range(4,len(sys.argv)):
    if isInt(sys.argv[x]) == False:
        print(error)
        sys.exit(1)

#옵션을 올바르게 입력했는지 검사
if sys.argv[1] == "-o" and sys.argv[2] == "A" and sys.argv[3] == "-i":
    for x in range(4,len(sys.argv)):
        inputList.append(int(sys.argv[x]))

    print(quicksort(inputList))

elif sys.argv[1] == "-o" and sys.argv[2] == "D" and sys.argv[3] == "-i":
    for x in range(4,len(sys.argv)):
        inputList.append(int(sys.argv[x]))

    quicksortD = quicksort(inputList)
    quicksortD.reverse()
    print(quicksortD)
    
else:
    print(error)
    sys.exit(1)
