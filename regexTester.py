'''
Created on Oct 19, 2012
Script to test regex against a file containing values 
to match.
@author 1aN0rmus@tekdefense.com
'''

import re

fileImport =open('example.txt')

strFile=''

for line in fileImport
    strFile += line

print(strFile)

regexValue = re.compile('Regex Here')
regexSearch = re.search(regexValue,strFile)

if(regexSearch)
        print('String Found '+regexSearch.group())
else
    print('Nothing Found')
    





if __name__ == '__main__'
    pass