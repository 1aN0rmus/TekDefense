#!/usr/bin/python
'''
Welcome to Automater! This script is used to list domains that an IP Address
resolves too, and tell if the domain is blacklisted.  This script currently queries
robtex.com and ipvoid.com for this info, but will include other sources in the future.
www.TekDefense.com
@author: 1aN0rmus@TekDefense.com
'''
import httplib2, re
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
-Filter out in-addr
-Filter out non-domains
-Fix IPvoid for IP's that haven't been scanned previously.  May need to submit instead of going straight to the URL.
-Add URL support
-Add command options (arguments)
-add nmap option
-pretty up
'''
ipInput = (raw_input('Please enter an IP address to be queried: '))
#urlInput = "tekdefense.com"

def main():
    
    
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
    
    rpd3 = re.compile('\<td\>ISP:.....\n\s+\<td\>\<a\s.+\>(.+)\<\/a\>', re.IGNORECASE)
    rpdFind3 = re.findall(rpd3,content2String)
    rpdSorted3=sorted(rpdFind3)
    
    rpd4 = re.compile('\<td\>IP\sCountry:.....\n\s+\<td\>\<img\ssrc=.+\salt=.+\s\<a\s.+\>(.+)\<\/a\>', re.IGNORECASE)
    rpdFind4 = re.findall(rpd4,content2String)
    rpdSorted4=sorted(rpdFind4)
    
    i=''
    for i in rpdSorted:
        if len(i)>4:
            if not i == ipInput:
                print (i)
    if i=='':
        print 'This IP does not resolve to a domain'
    
    print ''
    print 'Blacklist Status:'
    print '------------------------------' 
    
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
    
  
'''
74.125.232.102
188.95.52.162
ipvoid.com/scan/8.8.8.8/
http://whatismyipaddress.com/blacklist-check
http://www.mxtoolbox.com/SuperTool.aspx?action=blacklist%3a188.95.52.162
Regex 
('\/(.{1,20}\.\w{2,3})\.html'
>(.+\.\w{2,3})<\/a>
/<a [^>]*href="?([^">]+)"?>/
'(\w{1,20}\.(|\w {1,20}|\.)\w{2,3})\.html'
'''

if __name__ == "__main__":
    main()