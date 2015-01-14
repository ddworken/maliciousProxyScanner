#!/bin/python
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
