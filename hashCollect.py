#!/usr/bin/python

'''
This is HashCollect! This tool will scrape md5 hashes out of a specified file or URL
@TekDefense
Ian Ahl | www.TekDefense.com | 1aN0rmus@tekDefense.com
'''

import httplib2, re, sys, argparse, urllib, urllib2

parser = argparse.ArgumentParser(description='Hash Collector')
parser.add_argument('-u', '--url', help='This option is used to search for hashes on a website')
parser.add_argument('-f', '--file', help='This option is used to import a file that contains hashes')
parser.add_argument('-o', '--output', help='This option will output the results to a file.')
parser.add_argument('-r', '--regex', help='This option allows the user to set a custom regex value. Must incase in single or double quotes.')


args = parser.parse_args()
regVal = '[a-fA-F0-9]{32}'
listResults = []

if args.regex:
    regVal = str(args.regex)

if args.url == None and args.file == None:
    parser.print_help()

if args.output:
    oFile = args.output
    print '[+] Printing results to file:', args.output
    o = open(oFile, "w")
    sys.stdout = o

if args.file:
    iFile = args.file
    fileImport =open(iFile)
    strFile=''
    for line in fileImport:
        strFile += line    
    regexValue = re.compile(regVal)
    regexSearch = re.findall(regexValue,strFile)
    for i in regexSearch:
        listResults.append(i)
    
if args.url:
    url = args.url
    h = httplib2.Http(".cache")
    resp, content = h.request((url), "GET")
    contentString = (str(content))
    regexValue = re.compile(regVal)
    regexSearch = re.findall(regexValue,contentString)
    for i in regexSearch:
        listResults.append(i)
 
listResults = list(set(listResults))  
for i in listResults:
    print i
          

if __name__ == '__main__':
    pass
