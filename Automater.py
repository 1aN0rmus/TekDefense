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
Web Tools used are: IPvoid.com, Robtex.com, Fortiguard.com, unshorten.me, Urlvoid.com, Labs.alienvault.com
www.TekDefense.com
@author: 1aN0rmus@TekDefense.com, Ian Ahl
Version 1.2
'''
'''
Changelog:
1.2.1
[+] Modified regex in Robtex function to pick up "A" records that were being missed.
1.2
[+] Changed output style to @ViolentPython style
[+] Fixed IPVoid and URLVoid result for new regexes
[+] Fixed form submit for IP's and URLs that were not previously scanned
'''

#urlInput = "tekdefense.com"      
#ipInput = (raw_input('Please enter an IP address to be queried: '))

def main():   
    parser = argparse.ArgumentParser(description='IP and URL Passive Analysis tool')
    parser.add_argument('-t', '--target', help='List one IP Addresses to query.  Does not support more than one address.')
    parser.add_argument('-f', '--file', help='This option is used to import a file that contains IP Addresses or URLs')
    parser.add_argument('-o', '--output', help='This option will output the results to a file.')
    parser.add_argument('-e', '--expand', help='This option will expand a shortened url using unshort.me')
    parser.add_argument('-s', '--source', help='This option will only run the target against a specifc source engine to pull associated domains.  Options are robtex, ipvoid, fortinet, urlvoid, alienvault')
    args = parser.parse_args()
    if args.source == "robtex":
            ipInput = str(args.target)
            print args.source + " source engine selected"
            robtex(ipInput)
    if args.source == "ipvoid":
            ipInput = str(args.target)
            print args.source + " source engine selected"
            ipvoid(ipInput)
    if args.source == "fortinet":
            ipInput = str(args.target)
            print args.source + " source engine selected"
            fortiURL(ipInput)
    if args.source == "urlvoid":
            urlInput = str(args.target)
            print args.source + " source engine selected"
            urlvoid(urlInput)
    if args.source == "alienvault":
            ipInput = str(args.target)
            print args.source + " source engine selected"
            alienvault(ipInput)
    if args.target:
        if args.output != None:
            print '[+] Printing results to file:', args.output
            output = ""
            output = str(args.output)
            o = open(output, "w")
            sys.stdout = o
        if args.source != None:
            print "[*] operation complete"
        else: 
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
                print '--------------------------------'
                print '[*] ' + input + ' is an IP. ' 
                print '[*] Running IP toolset'
                ipInput = input
                robtex(ipInput)
                ipvoid(ipInput)
                fortiURL(ipInput)
                alienvault(ipInput)
            else:
                print '--------------------------------'
                print '[*] ' + input + ' is a URL.  '
                print '[*] Running URL toolset'
                urlInput = input
                unshortunURL(urlInput)
                urlvoid(urlInput)
                fortiURL(urlInput)
    elif args.file:
        if args.output != None:
            print '[*] Printing results to file:', args.output
            output = ""
            output = str(args.output)
            o = open(output, "w")
            sys.stdout = o  
        li = open(args.file).readlines()
        for i in li:
            li = str(i)
            ipInput = li.strip()
            input = ipInput
            if args.source != None:
                print "[*] operation complete"
            else:
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
                    print '--------------------------------'
                    print '[*] ' + input + ' is an IP.  Running IP toolset'
                    ipInput = input
                    robtex(ipInput)
                    ipvoid(ipInput)
                    fortiURL(ipInput)
                    alienvault(ipInput)
                else:
                    print '--------------------------------'
                    print '[*] ' + input + ' is a URL.  Running URL toolset'
                    urlInput = input
                    urlvoid(urlInput)
                    unshortunURL(urlInput)
                    fortiURL(urlInput)
        if args.expand != None:
            for i in li:
                li = str(i)
                ipInput = li.strip()
                url = ipInput
                unshortunURL(url)
                    
    elif args.expand:
        if args.output != None:
            print '[+] Printing results to file:', args.output
            output = ""
            output = str(args.output)
            o = open(output, "w")
            sys.stdout = o  
        url = args.expand
        unshortunURL(url)

def robtex(ipInput):   
    h1 = httplib2.Http(".cache")
    resp, content1 = h1.request(("http://robtex.com/" + ipInput), "GET")
    content1String = (str(content1))
    #print content1String

    rpd = re.compile('href\=\"\/\/.+\.robtex\.com\/(.+).html\"\s+\>.+\<\/a\>\s\<\/span\>\<\/td\>\n\<td\sclass\="\w+\"\scolspan\="\d*\"\>a', re.IGNORECASE)
    rpdFind = re.findall(rpd,content1String)
    
    rpdSorted=sorted(rpdFind)
    
    i=''
    for i in rpdSorted:
        if len(i)>4:
            if not i == ipInput:
                print '[+] A records from Robtex: ' + (i)
    if i=='':
        print '[-] This IP does not resolve to a domain'
    
    
def ipvoid(ipInput):                
    h2 = httplib2.Http(".cache")
    resp, content2 = h2.request(("http://ipvoid.com/scan/" + ipInput), "GET")
    content2String = (str(content2))
    rpderr = re.compile('An\sError\soccurred', re.IGNORECASE)
    rpdFinderr = re.findall(rpderr,content2String)
    # print content2String
    if "ERROR" in str(rpdFinderr):
        ipvoidErr = True
    else:
        ipvoidErr = False
    if ipvoidErr == False:
        rpd2 = re.compile('Detected\<\/font\>\<\/td..td..a.rel..nofollow..href.\"(.{6,70})\"\stitle\=\"View', re.IGNORECASE)
        rpdFind2 = re.findall(rpd2,content2String)
        rpdSorted2=sorted(rpdFind2)
    
        rpd3 = re.compile('ISP\<\/td\>\<td\>(.+)\<\/td\>', re.IGNORECASE)
        rpdFind3 = re.findall(rpd3,content2String)
        rpdSorted3=sorted(rpdFind3)
    
        rpd4 = re.compile('Country\sCode.+flag\"\s\/\>\s(.+)\<\/td\>', re.IGNORECASE)
        rpdFind4 = re.findall(rpd4,content2String)
        rpdSorted4=sorted(rpdFind4)

    
        j=''
        for j in rpdSorted2:
            print ('[+] Host is listed in blacklist at '+ j)
        if j=='':
            print('[-] IP is not listed in a blacklist')
       
        k=''
        for k in rpdSorted3:
            print ('[+] The ISP for this IP is: '+ k)
        if k=='':
            print('[-] No ISP listed')
        
        l=''
        for l in rpdSorted4:
            print ('[+] Geographic Location: '+ l)
        if l=='':
            print ('[-] No GEO location listed')
    else:
        print '[*] Scanning host now on IPVoid.com.  May take a few seconds.'

        url = ('http://www.ipvoid.com/')
        raw_params = {'ip':ipInput,'go':'Scan Now'}
        params = urllib.urlencode(raw_params)
        request = urllib2.Request(url,params,headers={'Content-type':'application/x-www-form-urlencoded'})
        page = urllib2.urlopen(request)
        page = page.read()
        content2String = str(page)
        
        rpd2 = re.compile('Detected\<\/font\>\<\/td..td..a.rel..nofollow..href.\"(.{6,70})\"\stitle\=\"View', re.IGNORECASE)
        rpdFind2 = re.findall(rpd2,content2String)
        rpdSorted2=sorted(rpdFind2)
    
        rpd3 = re.compile('ISP\<\/td\>\<td\>(.+)\<\/td\>', re.IGNORECASE)
        rpdFind3 = re.findall(rpd3,content2String)
        rpdSorted3=sorted(rpdFind3)
    
        rpd4 = re.compile('Country\sCode.+flag\"\s\/\>\s(.+)\<\/td\>', re.IGNORECASE)
        rpdFind4 = re.findall(rpd4,content2String)
        rpdSorted4=sorted(rpdFind4)

    
        j=''
        for j in rpdSorted2:
            print ('[+] Host is listed in blacklist at '+ j)
        if j=='':
            print('[-] IP is not listed in a blacklist')
       
        k=''
        for k in rpdSorted3:
            print ('[+] The ISP for this IP is: '+ k)
        if k=='':
            print('[-] No ISP listed')
        
        l=''
        for l in rpdSorted4:
            print ('[+] Geographic Location: '+ l)
        if l=='':
            print ('[-] No GEO location listed')
def fortiURL(ipInput):
    h3 = httplib2.Http(".cache")
    resp, content3 = h3.request(("http://www.fortiguard.com/ip_rep.php?data=" + ipInput + "&lookup=Lookup"), "GET")
    content3String = (str(content3))
    
    rpd5 = re.compile('Category:\s\<span\sstyle\=\"font\-size\:200\%\"\>(.+)\<\/span', re.IGNORECASE)
    rpdFind5 = re.findall(rpd5,content3String)
    rpdSorted5=sorted(rpdFind5)
    
    # print content3String
    m=''
    for m in rpdSorted5:
        print ('[+] FortiGuard URL Categorization: '+ m)
    if m=='':
        print ('[-] FortiGuard URL Categorization: Uncategorized')

def unshortunURL(url):
    h4 = httplib2.Http(".cache")
    resp, content4 = h4.request(("http://unshort.me/index.php?r=" + url), "GET")
    content4String = (str(content4))
    
    rpd6 = re.compile('result\"\>\s\<a\shref\=\".+\>(.+)\<\/a\>\s', re.IGNORECASE)
    rpdFind6 = re.findall(rpd6,content4String)
    rpdSorted6=sorted(rpdFind6)
    
    # print content3String

    m=''
    for m in rpdSorted6:
        if url not in m:
            print ('[+] ' + url + ' redirects to: ' + m)
        else:
            print ('[-] ' + url + ' is not a recognized shortened URL.')
def urlvoid(url):                
    h2 = httplib2.Http(".cache")
    resp, content2 = h2.request(("http://urlvoid.com/scan/" + url), "GET")
    content2String = (str(content2))
    rpderr = re.compile('An\sError\soccurred', re.IGNORECASE)
    rpdFinderr = re.findall(rpderr,content2String)
    # print content2String
    if "ERROR" in str(rpdFinderr):
        ipvoidErr = True
    else:
        ipvoidErr = False
    if ipvoidErr == False:
        
        rpd1 = re.compile('(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}).+Scan\swith\s', re.IGNORECASE)
        rpdFind1 = re.findall(rpd1,content2String)
        rpdSorted1=sorted(rpdFind1) 
        
        rpd2 = re.compile('DETECTED.{25,40}href\=\"(.{10,50})\"\stitle', re.IGNORECASE)
        rpdFind2 = re.findall(rpd2,content2String)
        rpdSorted2=sorted(rpdFind2)   

        rpd3 = re.compile('latitude\s\/\slongitude.+\<td\>(.+)\<\/td\>', re.IGNORECASE)
        rpdFind3 = re.findall(rpd3,content2String)
        rpdSorted3=sorted(rpdFind3)
        
        rpd4 = re.compile('alt\=\"flag\".+\>(.+)\<\/td\>', re.IGNORECASE)
        rpdFind4 = re.findall(rpd4,content2String)
        rpdSorted4=sorted(rpdFind4)
        
        rpd5 = re.compile('Domain\s1st\sRegistered.+\<td\>(.+)\<\/td\>', re.IGNORECASE)
        rpdFind5 = re.findall(rpd5,content2String)
        rpdSorted5=sorted(rpdFind5)
        
        i=''
        for i in rpdSorted1:
            print ('[+] Host IP Address is '+ i)
        if i=='':
            print('[-] IP is not listed')
        
        j=''
        for j in rpdSorted2:
            print ('[+] Host is listed in blacklist at '+ j)
        if j=='':
            print('[-] IP is not listed in a blacklist')
       
        k=''
        for k in rpdSorted3:
            print ('[+] Latitude / Longitude: '+ k)
        if k=='':
            print('[-] No Latitude / Longitude listed')
        
        l=''
        for l in rpdSorted4:
            print ('[+] Country: '+ l)
        if l=='':
            print ('[-] No Country listed')
        
        m=''
        for m in rpdSorted5:
            print ('[+] Domain creation date: '+ m)
        if m=='':
            print ('[-] Domain creation date not listed.')
    else:
        print '[*] Scanning host now on URLVoid.com.  May take a few seconds.'
        urlvoid = ('http://www.urlvoid.com/')
        raw_params = {'url':url,'Check':'Submit'}
        params = urllib.urlencode(raw_params)
        request = urllib2.Request(urlvoid,params,headers={'Content-type':'application/x-www-form-urlencoded'})
        page = urllib2.urlopen(request)
        page = page.read()
        content2String = str(page)
        #print content2String
        rpd1 = re.compile('(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}).+Scan\swith\s', re.IGNORECASE)
        rpdFind1 = re.findall(rpd1,content2String)
        rpdSorted1=sorted(rpdFind1) 
        
        rpd2 = re.compile('DETECTED.{25,40}href\=\"(.{10,50})\"\stitle', re.IGNORECASE)
        rpdFind2 = re.findall(rpd2,content2String)
        rpdSorted2=sorted(rpdFind2)   

        rpd3 = re.compile('latitude\s\/\slongitude.+\<td\>(.+)\<\/td\>', re.IGNORECASE)
        rpdFind3 = re.findall(rpd3,content2String)
        rpdSorted3=sorted(rpdFind3)
        
        rpd4 = re.compile('alt\=\"flag\".+\>(.+)\<\/td\>', re.IGNORECASE)
        rpdFind4 = re.findall(rpd4,content2String)
        rpdSorted4=sorted(rpdFind4)
        
        rpd5 = re.compile('Domain\s1st\sRegistered.+\<td\>(.+)\<\/td\>', re.IGNORECASE)
        rpdFind5 = re.findall(rpd5,content2String)
        rpdSorted5=sorted(rpdFind5)
        
        i=''
        for i in rpdSorted1:
            print ('[+] Host IP Address is '+ i)
        if i=='':
            print('[-] IP is not listed')
        
        j=''
        for j in rpdSorted2:
            print ('[+] Host is listed in blacklist at '+ j)
        if j=='':
            print('[-] IP is not listed in a blacklist')
       
        k=''
        for k in rpdSorted3:
            print ('[+] Latitude / Longitude: '+ k)
        if k=='':
            print('[-] No Latitude / Longitude listed')
        
        l=''
        for l in rpdSorted4:
            print ('[+] Country: '+ l)
        if l=='':
            print ('[-] No Country listed')
        
        m=''
        for m in rpdSorted5:
            print ('[+] Domain creation date: '+ m)
        if m=='':
            print ('[-] Domain creation date not listed.')

def alienvault(ipInput):
    h1 = httplib2.Http(".cache")
    url = "http://labs.alienvault.com/labs/index.php/projects/open-source-ip-reputation-portal/information-about-ip/?ip=" + ipInput 
    resp, conten1 = h1.request((url), "GET")
    content1String = (str(conten1))
    
    rpd = re.compile('.*IP not found.*')
    rpdFind = re.findall(rpd,content1String)

    if not rpdFind:
        print ('[+] IP is listed in AlienVault IP reputation database at ' + url)
    else:
        print ('[-] IP is not listed in AlienVault IP reputation database')
        

if __name__ == "__main__":
    main()
