#!/usr/bin/python

'''
Created on Oct 19, 2012
Script to test regex against a file containing values 
to match.
@author 1aN0rmus@tekdefense.com
'''

import re

fileImport =open('sample.txt')

strFile=''

for line in fileImport:
    strFile += line

print(strFile)

regexValue = re.compile('\d{1,5}\s\w+\s\w{1,3}\.')
regexSearch = re.findall(regexValue,strFile)

if(regexSearch):
        print('String Found: '+ str(regexSearch))
else:
    print('Nothing Found')
