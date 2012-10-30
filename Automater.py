#!/usr/bin/python

import httplib2, re, sys, getopt
#ipInput = 'IP PLACEHOLDER'

print ''' 
 ___        _                        _            
 / _ \      | |                      | |           
/ /_\ \_   _| |_ ___  _ __ ___   __ _| |_ ___ _ __ 
|  _  | | | | __/ _ \| '_ ` _ \ / _` | __/ _ \ '__|
| | | | |_| | || (_) | | | | | | (_| | ||  __/ |   
\_| |_/\__,_|\__\___/|_| |_| |_|\__,_|\__\___|_|   

Welcome to Automater! This script is used to list domains that an IP Address
resolves too, and tell if the domain is blacklisted.  This script currently queries
robtex.com and ipvoid.com for this info, but will include other sources in the future.
www.TekDefense.com
@author: 1aN0rmus@TekDefense.com
'''
'''
To do:
-Filter out domain duplicates (Complete)
-Filter out in-addr (Complete)
-Filter out non-domains (Complete?)
-URL Filtering Check (Complete)
-Multiple IPs and URLs
-import list
-output to file
-******* Fix IPvoid for IP's that haven't been scanned previously. ********
-Add URL support
-Add command options/arguments
-add nmap option
-pretty up
-Add malwaredomainlist checker
-more blacklist sources
'''

#urlInput = "tekdefense.com"
def usage():
    print '''
    This does not work yet, just a placeholder 
    -t: target ip or url.  URL must include http://
    -s: source engine (robtex, ipvoid, fortiguard)
    -a: all engines
    -h: help
    -f: import a file of IPs and/or URLs
    -o: output results to file
    Examples:
    ./Automater.py -t 123.123.123.123 -a -o result.txt
    ./Automater.py -f hosts.txt -s robtex -o results.txt
    '''


'''    
def start(argv):
    if len(sys.argv) < 4:
        usage()
        sys.exit()
    try :
           opts, args = getopt.getopt(argv, "l:d:b:s:vf:nhcte:")
    except getopt.GetoptError:
               usage()
        sys.exit()
'''

'''
    try:
        opts, args = getopt.getopt(argv, "h:d", ["Help", "ipInput="])
    except getopt.GetoptError:
        usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt == '-d':
            ipInput = arg
            
        source = "".join(args)

        p = Automater(ipInput, source)
              
        print p.output()
'''      
      
      
ipInput = (raw_input('Please enter an IP address to be queried: '))

def main():
    #usage()
    robtex(ipInput)
    ipvoid(ipInput)
    fortiURL(ipInput)

def robtex(ipInput):    
    h1 = httplib2.Http(".cache")
    resp, content1 = h1.request(("http://robtex.com/" + ipInput), "GET")
    content1String = (str(content1))
    #print content1String

    rpd = re.compile('\s>(.{1,20})\<\/a>\s\<\/span\>\<\/td\>\n\<td\sclass="..."\s...........\>a', re.IGNORECASE)
    rpdFind = re.findall(rpd,content1String)
    
    rpdSorted=sorted(rpdFind)
    
    print ''
    print ('Generating report for ' + ipInput)
    print ''
    print 'This IP Address resolves to the following domains(A Records only):'
    print '------------------------------' 
    
    i=''
    for i in rpdSorted:
        if len(i)>4:
            if not i == ipInput:
                print (i)
    if i=='':
        print 'This IP does not resolve to a domain'
    
    
def ipvoid(ipInput):                
    h2 = httplib2.Http(".cache")
    resp, content2 = h2.request(("http://ipvoid.com/scan/" + ipInput), "GET")
    content2String = (str(content2))
    '''
    TESTING POST METHOD, NO WORKIE THOUGH.
    from httplib2 import Http
    from urllib import urlencode
    h = Http()
    data = dict(url = ipInput)
    resp, content = h.request("http://ipvoid.com", "POST", urlencode(data))
    print (content)
    '''
    #print(content2String)
    rpd2 = re.compile('\>DETECTED\<span\>\<\/td\>\n\s+<td\>\<a\srel="nofollow"\shref="(\w+:\/\/.+)"\s', re.IGNORECASE)
    rpdFind2 = re.findall(rpd2,content2String)
    rpdSorted2=sorted(rpdFind2)
    
    print ''
    print 'Blacklist Status:'
    print '------------------------------' 
    
    rpd3 = re.compile('\<td\>ISP:.....\n\s+\<td\>\<a\s.+\>(.+)\<\/a\>', re.IGNORECASE)
    rpdFind3 = re.findall(rpd3,content2String)
    rpdSorted3=sorted(rpdFind3)
    
    rpd4 = re.compile('\<td\>IP\sCountry:.....\n\s+\<td\>\<img\ssrc=.+\salt=.+\s\<a\s.+\>(.+)\<\/a\>', re.IGNORECASE)
    rpdFind4 = re.findall(rpd4,content2String)
    rpdSorted4=sorted(rpdFind4)

    
    j=''
    for j in rpdSorted2:
        print ('Host is listed in blacklist at '+ j)
    if j=='':
        print('IP is not listed in a blacklist')
    
    print ''    
    print 'IP ISP and Geo Location:'
    print '------------------------------' 
       
    k=''
    for k in rpdSorted3:
        print ('The ISP for this IP is: '+ k)
    if k=='':
        print('No ISP listed')
        
    l=''
    for l in rpdSorted4:
        print ('Geographic Location: '+ l)
    if l=='':
        print ('No GEO location listed')

def fortiURL(ipInput):
    h3 = httplib2.Http(".cache")
    resp, content3 = h3.request(("http://www.fortiguard.com/ip_rep.php?data=" + ipInput + "&lookup=Lookup"), "GET")
    content3String = (str(content3))
    
    rpd5 = re.compile('Category:\s\<span\sstyle\=\"font\-size\:200\%\"\>(.+)\<\/span', re.IGNORECASE)
    rpdFind5 = re.findall(rpd5,content3String)
    rpdSorted5=sorted(rpdFind5)
    
    # print content3String
    print ''
    print 'FortiGuard URL Classification:'
    print '------------------------------'  
    m=''
    for m in rpdSorted5:
        print ('URL Categorization: '+ m)
    if m=='':
        print ('Uncategorized')
  
'''
74.125.232.102
188.95.52.162
http://www.mxtoolbox.com/SuperTool.aspx?action=blacklist%3a188.95.52.162
('\/(.{1,20}\.\w{2,3})\.html'
>(.+\.\w{2,3})<\/a>
/<a [^>]*href="?([^">]+)"?>/
'(\w{1,20}\.(|\w {1,20}|\.)\w{2,3})\.html'
'''

if __name__ == "__main__":
    main()
#     try: start(sys.argv[1:])
#    except KeyboardInterrupt:
#        print "Search interrupted by user.."
#    except:
#        sys.exit()