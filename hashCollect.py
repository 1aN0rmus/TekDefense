#!/usr/bin/python

'''
This is HashCollect! This tool will scrape md5 hashes out of a specified file or URL
@TekDefense
Ian Ahl | www.TekDefense.com | 1aN0rmus@tekDefense.com
*Some of the Regular Expressions were taken from http://gskinner.com/RegExr/
'''

import httplib2, re, sys, argparse, urllib, urllib2

parser = argparse.ArgumentParser(description='Hash Collector')
parser.add_argument('-u', '--url', help='This option is used to search for hashes on a website')
parser.add_argument('-f', '--file', help='This option is used to import a file that contains hashes')
parser.add_argument('-o', '--output', help='This option will output the results to a file.')
parser.add_argument('-r', '--regex', help='This option allows the user to set a custom regex value. Must incase in single or double quotes.')
parser.add_argument('-t', '--type', help='THis is help')



args = parser.parse_args()
regVal = '[a-fA-F0-9]{32}'
listResults = []

if args.type:
    if args.type == 'MD5':
        regVal = '[a-fA-F0-9]{32}'
    if args.type == 'SHA1':
        regVal = '[a-fA-F0-9]{40}'
    if args.type == 'SHA256':
        regVal = '[a-fA-F0-9]{64}'
    if args.type == 'LM':
        regVal = '[a-fA-F0-9]{32}'
    if args.type == 'DOMAIN':
        regVal = '([a-zA-Z0-9-]+\.)(com|net|biz|cat|aero|asia|coop|info|int|jobs|mobi|museum|name|org|post|pre|tel|travel|xxx|edu|gov|mil|br|cc|ca|uk|ch|co|cx|de|fr|hk|jp|kr|nl|nr|ru|tk|ws|tw)'
    if args.type == 'URL':
        regVal = '(http\:\/\/|https\:\/\/)([a-zA-Z0-9-]+\.)(com|net|biz|cat|aero|asia|coop|info|int|jobs|mobi|museum|name|org|post|pre|tel|travel|xxx|edu|gov|mil|br|cc|ca|uk|ch|co|cx|de|fr|hk|jp|kr|nl|nr|ru|tk|ws|tw)'
    if args.type == 'IP4':
        regVal = '((?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(?![0-9]))'
    if args.type == 'IP6':
        regVal = '(((([01]? d?\\d)|(2[0-5]{2}))\\.){3}(([01]?\\d?\\d)|(2[0-5]{2})))|(([A-F0-9]){4}(:|::)){1,7}(([A-F0-9]){4})'
    if args.type == 'SSN':
        regVal = '(\d{3}\-\d{2}\-\d{3})|(\d{3}\s\d{2}\s\d{3})'
    if args.type == 'EMAIL':
        regVal = '([a-zA-Z0-9\.-_]+@)([a-zA-Z0-9-]+\.)(com|net|biz|cat|aero|asia|coop|info|int|jobs|mobi|museum|name|org|post|pre|tel|travel|xxx|edu|gov|mil|br|cc|ca|uk|ch|co|cx|de|fr|hk|jp|kr|nl|nr|ru|tk|ws|tw)'
    if args.type == 'CCN':
        regVal = '\d{14,16}|\d{4}\s\d{4}\s\d{4}\s\d{2,4}|\d{4}\-\d{4}\-\d{4}\-\d{2,4}'

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
    print ''.join(i)
          

if __name__ == '__main__':
    pass
