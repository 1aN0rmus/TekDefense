#!/usr/bin/python

'''
This is tekCollect! This tool will scrape specified data types out of a URL or file.
@TekDefense
Ian Ahl | www.TekDefense.com | 1aN0rmus@tekDefense.com
*Some of the Regular Expressions were taken from http://gskinner.com/RegExr/
Version: 0.4

Changelog:
.4
[+] Fixed issue where -t IP4 returned URLs
[+] Added summary functions that shows what types of data are in a specified target.
[+] Modified the regex for many of the data types for better results
[+] Added several new data types: zip, twitter, doc, exe, MYSQL hash, Wordpress (WP) hash, IMG
[+] Modified the way summary is displayed
.3
[+] Added predefined data types that can be invoke with -t type
.2
[+] Expanded the script to allow custom regex with a -r 'regex here'
.1
[+] Replaced listTypes selction with loop
[+] Tool created and can only pull md5 hashes

TODO
[-] Proper hash values matching 
[-] Ability to accept multiple --types
[-] Improved menu selections & functions
'''

import httplib2, re, sys, argparse

# Adding arguments
parser = argparse.ArgumentParser(description='tekCollect is a tool that will scrape a file or website for specified data')
parser.add_argument('-u', '--url', help='This option is used to search for hashes on a website')
parser.add_argument('-f', '--file', help='This option is used to import a file that contains hashes')
parser.add_argument('-o', '--output', help='This option will output the results to a file.')
parser.add_argument('-r', '--regex', help='This option allows the user to set a custom regex value. Must incase in single or double quotes.')
parser.add_argument('-t', '--type', help='This option allows a user to choose the type of data they want to pull out. Currently MD5, SHA1, SHA 256, Domain, URL, IP4, IP6, CCN, SSN, EMAIL')
parser.add_argument('-s', '--summary', action='store_true', default=False, help='This options will show a summary of the data types in a file')
args = parser.parse_args()

# Setting some variables and lists 
regVal = '[a-fA-F0-9]{32}'    # Initial revVal
listResults = []
MD5 = '[a-fA-F0-9]{32}'
SHA1 = '[a-fA-F0-9]{40}'
SHA256 = '[a-fA-F0-9]{64}'
LM = '[a-fA-F0-9]{32}'
DOMAIN = '\W(\w+\.){1,4}(com|net|biz|cat|aero|asia|coop|info|int|jobs|mobi|museum|name|org|post|pre|tel|travel|xxx|edu|gov|mil|br|cc|ca|uk|ch|co|cx|de|fr|hk|jp|kr|nl|nr|ru|tk|ws|tw)[^a-fA-F0-9_-]'
URL = '(http\:\/\/|https\:\/\/)([a-zA-Z0-9-]+\.)(com|net|biz|cat|aero|asia|coop|info|int|jobs|mobi|museum|name|org|post|pre|tel|travel|xxx|edu|gov|mil|br|cc|ca|uk|ch|co|cx|de|fr|hk|jp|kr|nl|nr|ru|tk|ws|tw)\W'
IP4 = '((?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(?![0-9]))'
IP6 = '(((([01]? d?\\d)|(2[0-5]{2}))\\.){3}(([01]?\\d?\\d)|(2[0-5]{2})))|(([A-F0-9]){4}(:|::)){1,7}(([A-F0-9]){4})'
SSN = '(\d{3}\-\d{2}\-\d{3})|(\d{3}\s\d{2}\s\d{3})'
EMAIL = '([a-zA-Z0-9\.-_]+@)([a-zA-Z0-9-]+\.)(com|net|biz|cat|aero|asia|coop|info|int|jobs|mobi|museum|name|org|post|pre|tel|travel|xxx|edu|gov|mil|br|cc|ca|uk|ch|co|cx|de|fr|hk|jp|kr|nl|nr|ru|tk|ws|tw)\W'
CCN = '\d{4}\s\d{4}\s\d{4}\s\d{2,4}|\d{4}\-\d{4}\-\d{4}\-\d{2,4}'
TWITTER = '(?<=^|(?<=[^a-zA-Z0-9-_\.]))(@)([A-Za-z]+[A-Za-z0-9]+)'
PHONE = ''
NTLM = ''
DOC = '\W([\w-]+\.)(docx|doc|csv|pdf|xlsx|xls|rtf|txt|pptx|ppt)'
EXE = '\W([\w-]+\.)(exe|dll)'
ZIP = '\W([\w-]+\.)(zip|zipx|7z|rar|tar|gz)'
IMG = '\W([\w-]+\.)(jpeg|jpg|gif|png|tiff|bmp)'
MYSQL = '\*[a-fA-F0-9]{40}'
WP = '\$P\$\w{31}'
CISCO5 = ''
CISCO7 = ''


listTypes = [   ('MD5',MD5),
		        ('SHA1',SHA1), 
        		('SHA256',SHA256), 
        		('MYSQL', MYSQL), 
    	    	('WP', WP), 
        		('DOMAIN', DOMAIN), 
    		    ('URL', URL), 
    	    	('EMAIL',EMAIL), 
        		('TWITTER', TWITTER), 
        		('IP4',IP4), 
        		('IP6',IP6), 
        		('DOC', DOC), 
        		('EXE', EXE), 
        		('ZIP', ZIP), 
        		('IMG', IMG), 
        		('SSN', SSN), 
    		    ('CCN',CCN)]

# Determining what type of data the user wants and setting the regex to the regVal variable for that data type
if args.type:
    for t in listTypes:
		if args.type.upper() == t[0]:
			regVal = t[1]
            
# If the user puts in a data type we do not have defined above, then let them know what types of data are available.
else:
    print '\t[-] ' + args.type + ' is not a valid type. \n\tCurrent valid types are MD5, SHA1, SHA256, DOMAIN, URL, IP4, IP6, SSN, EMAIL, and CCN'
	sys.exit()

# If the user wants to set a custom regex, it is collected here and added to the regVal variable.
if args.regex:
    regVal = str(args.regex)

# If the user does not give us a file or url to scrape show help and exit.
if args.url == None and args.file == None:
    parser.print_help()
    sys.exit()

# If the user wants to output the results to a file this will collect the name of the file and redirect all sys.stdout to that file
if args.output:
    oFile = args.output
    print '[+] Printing results to file:', args.output
    o = open(oFile, "w")
    sys.stdout = o

# If the target to scrape is a file open the file create a string for each line, regex the string for the data type specified by the regVal, and put results in a list.
if args.file:
    if args.Summary == True:
        iFile = args.file
        fileImport =open(iFile)
        strFile=''
        print '[*] Summary of files types for: ' + iFile        
        for line in fileImport:
            strFile += line
        for i in listTypes:
            regVal = i[1]
            regexValue = re.compile(regVal)
            regexSearch = re.findall(regexValue,strFile)
            listResults = []
            for j in regexSearch:
                listResults.append(j)
            #for i in tup in 
            listResults = list(set(listResults)) 
            for k in listResults:
                ''.join(k) 
            print '[+]' + i[0] + ': ' + str(len(listResults))
        sys.exit()  
    else:
        iFile = args.file
        fileImport =open(iFile)
        strFile=''
        for line in fileImport:
            strFile += line    
        #print strFile
        regexValue = re.compile(regVal)
        regexSearch = re.findall(regexValue,strFile)
        for i in regexSearch:
            listResults.append(i)

# If the target to scrape is a url conect to and get content from the url, create a string out of the content, regex the string for the data type specified by the regVal, and put results in a list.    
if args.url:
    if args.summary == True:
        url = args.url
        h = httplib2.Http(".cache")
        resp, content = h.request((url), "GET")
        contentString = (str(content))
        print '[*] Summary of files types for: ' + url
        for i in listTypes:
            regVal = i[1]
            regexValue = re.compile(regVal)
            regexSearch = re.findall(regexValue,contentString)
            listResults = []
            for j in regexSearch:
                listResults.append(j)
            #for i in tup in 
            listResults = list(set(listResults)) 
            for k in listResults:
                ''.join(k) 
            print '[+]' + i[0] + ': ' + str(len(listResults))
        sys.exit()
    else:
        url = args.url
        h = httplib2.Http(".cache")
        resp, content = h.request((url), "GET")
        contentString = (str(content))
        regexValue = re.compile(regVal)
        regexSearch = re.findall(regexValue,contentString)
        for i in regexSearch:
            listResults.append(i)

# Remove duplicates from the list and print
listResults = list(set(listResults))  
for i in listResults:
    print ''.join(i)
 

if __name__ == '__main__':
    pass
