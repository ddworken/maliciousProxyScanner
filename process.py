#!/bin/python
#This program will automatically go through a file called 'output.txt' searching for injected javascript code. 
#For any injected javascript code, it will print out the line containing injected javascript and IP address and
#port for the proxy that injected said javascript. 
malicious = []
ip = []
with open('output.txt') as f:
    input = f.readlines()
for line in input:
    line = line.rstrip('\n')
#lastIP = ""
for line in input:
    lineT = line.lower()
    if "[-]" in line:
        lastIP = line
    if "+" in line and (("javascript" in line) or ("js" in line)):
        ip.append(lastIP)
        malicious.append(line)
for index, line in enumerate(malicious):
    print ip[index]
    print line
