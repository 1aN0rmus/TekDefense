#!/usr/bin/python

import httplib2, re, sys, argparse, urllib, urllib2

print ''' 
 ___        _                        _            
 / _ \      | |                      | |           
/ /_\ \_   _| |_ ___  _ __ ___   __ _| |_ ___ _ __ 
|  _  | | | | __/ _ \| '_ ` _ \ / _` | __/ _ \ '__|
| | | | |_| | || (_) | | | | | | (_| | ||  __/ |   
\_| |_/\__,_|\__\___/|_| |_| |_|\__,_|\__\___|_|   

Welcome to Automater! I have created this tool to help analyst investigate IP Addresses and URLs with the common web based tools.  All activity is passive so it will not alert attackers.
Web Tools used are:
IPvoid.com, Robtex.com, Fortiguard.com, unshorten.me, Urlvoid.com 
www.TekDefense.com
@author: 1aN0rmus@TekDefense.com
'''
'''
To do:
-Filter out domain duplicates (Complete)
-Filter out in-addr (Complete)
-Filter out non-domains (Complete?)
-URL Filtering Check (Complete)
-Multiple IPs and URLs (Complete)
-import list (Complete)
-output to file (Complete)
-Fix IPvoid for IP's that haven't been scanned previously. (Complete)
-Add URL support (Complete)
-Add command options/arguments (Complete, Yay Argparse!)
-Add malwaredomainlist checker
-unshorten url (Complete)
-timeout function
-export to csv
-export to html
-pretty up code
-Pretty up output
'''

#urlInput = "tekdefense.com"      
#ipInput = (raw_input('Please enter an IP address to be queried: '))

def main():   
    parser = argparse.ArgumentParser(description='This is Automater Biotch!')
    parser.add_argument('-t', '--target', help='List one IP Addresses to query.  Does not support more than one address.')
    parser.add_argument('-f', '--file', help='This option is used to import a file that contains IP Addresses or URLs')
    parser.add_argument('-o', '--output', help='This option will output the results to a file.')
    parser.add_argument('-e', '--expand', help='This option will expand a shortened url using unshort.me')
    args = parser.parse_args()
    if args.target:
        if args.output != None:
            print 'Printing results to file:', args.output
            output = ""
            output = str(args.output)
            o = open(output, "w")
            sys.stdout = o  
        input = args.target
        rpd7 = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', re.IGNORECASE)
        rpdFind7 = re.findall(rpd7,input)
        rpdSorted7=sorted(rpdFind7)
        rpdSorted7=str(rpdSorted7)
        rpdSorted7=rpdSorted7[2:-2]
    
        rpd8 = re.compile('([-a-z0-9A-Z]+\.[-a-z0-9A-Z]*).+', re.IGNORECASE)
        rpdFind8 = re.findall(rpd8,input)
        rpdSorted8=sorted(rpdFind8)
        rpdSorted8=str(rpdSorted8)
        rpdSorted8=rpdSorted8[2:-2]
        if rpdSorted7 == input:
            print '------------------------------'
            print '------------------------------'
            print input + ' is an IP.  Running IP toolset'
            print '------------------------------'
            print '------------------------------'
            ipInput = input
            robtex(ipInput)
            ipvoid(ipInput)
            fortiURL(ipInput)
        else:
            print '------------------------------'
            print '------------------------------'
            print input + ' is a URL.  Running URL toolset'
            print '------------------------------'
            print '------------------------------'
            urlInput = input
            unshortunURL(urlInput)
            urlvoid(urlInput)
    elif args.file:
        if args.output != None:
            print 'Printing results to file:', args.output
            output = ""
            output = str(args.output)
            o = open(output, "w")
            sys.stdout = o  
        li = open(args.file).readlines()
        for i in li:
            li = str(i)
            ipInput = li.strip()
            input = ipInput
            rpd7 = re.compile('\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', re.IGNORECASE)
            rpdFind7 = re.findall(rpd7,input)
            rpdSorted7=sorted(rpdFind7)
            rpdSorted7=str(rpdSorted7)
            rpdSorted7=rpdSorted7[2:-2]
    
            rpd8 = re.compile('([-a-z0-9A-Z]+\.[-a-z0-9A-Z]*).+', re.IGNORECASE)
            rpdFind8 = re.findall(rpd8,input)
            rpdSorted8=sorted(rpdFind8)
            rpdSorted8=str(rpdSorted8)
            rpdSorted8=rpdSorted8[2:-2]
            if rpdSorted7 == input:
                print '------------------------------'
                print '------------------------------'
                print input + ' is an IP.  Running IP toolset'
                print '------------------------------'
                print '------------------------------'
                ipInput = input
                robtex(ipInput)
                ipvoid(ipInput)
                fortiURL(ipInput)
                print ''
                print ''
            else:
                print '------------------------------'
                print '------------------------------'
                print input + ' is a URL.  Running URL toolset'
                print '------------------------------'
                print '------------------------------'
                urlInput = input
                urlvoid(urlInput)
                unshortunURL(urlInput)
                print ''
                print ''
                
    elif args.expand:
        url = args.expand
        unshortunURL(url)

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
    rpderr = re.compile('\<div\sclass\=\"error\"\>', re.IGNORECASE)
    rpdFinderr = re.findall(rpderr,content2String)
    if "error" in str(rpdFinderr):
        ipvoidErr = True
    else:
        ipvoidErr = False
    if ipvoidErr == False:
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
    else:
        print '------------------------------'
        print 'Scanning host now on IPVoid.com.  May take a few seconds.'
        print '------------------------------'
        url = ('http://www.ipvoid.com/scan/'+ipInput)
        raw_params = {'url':ipInput,'go':'Scan Now'}
        params = urllib.urlencode(raw_params)
        request = urllib2.Request(url,params,headers={'Content-type':'application/x-www-form-urlencoded'})
        page = urllib2.urlopen(request)
        page = page.read()
        content2String = str(page)
        
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

def unshortunURL(url):
    h4 = httplib2.Http(".cache")
    resp, content4 = h4.request(("http://unshort.me/index.php?r=" + url), "GET")
    content4String = (str(content4))
    
    rpd6 = re.compile('result\"\>\s\<a\shref\=\".+\>(.+)\<\/a\>\s', re.IGNORECASE)
    rpdFind6 = re.findall(rpd6,content4String)
    rpdSorted6=sorted(rpdFind6)
    
    # print content3String
    print ''
    print 'URL UnShortner:'
    print '------------------------------'  
    m=''
    for m in rpdSorted6:
        if url not in m:
            print (url + ' redirects to: ' + m)
        else:
            print (url + ' is not a recognized shortened URL.')
def urlvoid(url):                
    h2 = httplib2.Http(".cache")
    resp, content2 = h2.request(("http://urlvoid.com/scan/" + url), "GET")
    content2String = (str(content2))
    rpderr = re.compile('\<div\sclass\=\"error\"\>', re.IGNORECASE)
    rpdFinderr = re.findall(rpderr,content2String)
    if "error" in str(rpdFinderr):
        ipvoidErr = True
    else:
        ipvoidErr = False
    if ipvoidErr == False:
        
        rpd1 = re.compile('\<td\>IP\sAddress:\<\/td\>\n\s+\<td\>\n\s+\<a\shref=\"\/ip\/(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}).+\n\s+\<\/td>', re.IGNORECASE)
        rpdFind1 = re.findall(rpd1,content2String)
        rpdSorted1=sorted(rpdFind1) 
        
        rpd2 = re.compile('\>DETECTED\<span\>\<\/td\>\n\s+<td\>\<a\srel="nofollow"\shref="(\w+:\/\/.+)"\s', re.IGNORECASE)
        rpdFind2 = re.findall(rpd2,content2String)
        rpdSorted2=sorted(rpdFind2)   

        rpd3 = re.compile('\<td\>ISP:\<\/td\>\n\s+\<td\>(.+)\<\/td>', re.IGNORECASE)
        rpdFind3 = re.findall(rpd3,content2String)
        rpdSorted3=sorted(rpdFind3)
        
        rpd4 = re.compile('\<td\>IP\sCountry:\<\/td\>\n\s+\<td\>.+\/\>\s(.+)\<\/td>', re.IGNORECASE)
        rpdFind4 = re.findall(rpd4,content2String)
        rpdSorted4=sorted(rpdFind4)
        
        rpd5 = re.compile('\<td\>Domain\sCreated:\<\/td\>\n\s+\<td\>(.+)\<\/td>', re.IGNORECASE)
        rpdFind5 = re.findall(rpd5,content2String)
        rpdSorted5=sorted(rpdFind5)
        
        print ''    
        print 'IP Address:'
        print '------------------------------' 
        
        i=''
        for i in rpdSorted1:
            print ('Host IP Address is '+ i)
        if i=='':
            print('IP is not listed')
    
        
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
            print ('ISP: '+ k)
        if k=='':
            print('No ISP listed')
        
        l=''
        for l in rpdSorted4:
            print ('Geographic Location: '+ l)
        if l=='':
            print ('No GEO location listed')
        
        m=''
        for m in rpdSorted5:
            print ('Domain creation date: '+ m)
        if m=='':
            print ('Domain creation date not listed.')

    
'''
(?:\d{1,3}\.){3}\d{1,3}|                    (?# IPv4 address)
[:a-fA-F0-9]*:[:a-fA-F0-9]*:[:a-fA-F0-9.]*| (?# IPv6 address)
                (?# domain name)
http://unshort.me/index.php?r=bit.ly/XDlV1q
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