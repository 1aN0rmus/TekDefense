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
@author: 1aN0rmus@TekDefense.com, Ian Ahl, @TekDefense
Version 1.2.4
'''
'''
Changelog:
1.2.4
[+] Modifed Robtex data pull to match sites new formatting
[+] Added Virustotal search for the hash function
1.2.3
[+] Added HTTP Proxy support. Will pull OS default proxy settings.
[+] Modified some variables for consistency 
[+] Added comments
[-] Removed JoeBox from hash search
1.2.2
[+] Fixed FortiGuard rating https://github.com/1aN0rmus/TekDefense/issues/10
[+] Display help when no arguments are given https://github.com/1aN0rmus/TekDefense/issues/8
[+] Added Hash Search functionality https://github.com/1aN0rmus/TekDefense/issues/7
[+] Sources for Hash search are VxVault, ThreatExpert, JoeSandBox, and Minotaur
1.2.1
[+] Modified regex in Robtex function to pick up "A" records that were being missed.
[+] Alienvault reputation data added by guillermogrande.  Thank you!
1.2
[+] Changed output style to @ViolentPython style
[+] Fixed IPVoid and URLVoid result for new regexes
[+] Fixed form submit for IP's and URLs that were not previously scanned
'''

def main():   
    # Adding arguments
    parser = argparse.ArgumentParser(description='IP, URL, and Hash Passive Analysis tool')
    parser.add_argument('-t', '--target', help='List one IP Addresses, URL or Hash to query.  Does not support more than one address.')
    parser.add_argument('-f', '--file', help='This option is used to import a file that contains IP Addresses, URLs or Hashes')
    parser.add_argument('-o', '--output', help='This option will output the results to a file.')
    parser.add_argument('-e', '--expand', help='This option will expand a shortened url using unshort.me')
    parser.add_argument('-s', '--source', help='This option will only run the target against a specific source engine to pull associated domains.  Options are robtex, ipvoid, fortinet, urlvoid, alienvault')
    args = parser.parse_args()
    # If no -t or -f is given show the help
    if args.target == None and args.file == None:
        parser.print_help()
        sys.exit(1)
    # Options to run individual source engines
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
            targetID(args.target)
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
                targetID(input)
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
    proxy = urllib2.ProxyHandler()
    opener = urllib2.build_opener(proxy)
    response = opener.open("http://robtex.com/" + ipInput)
    content = response.read()
    contentString = str(content)
    print contentString
    rpd = re.compile('host\.robtex\.com.+\s\>(.+)\<\/a\>', re.IGNORECASE)
    rpdFind = re.findall(rpd,contentString)
    
    rpdSorted=sorted(rpdFind)
    
    i=''
    for i in rpdSorted:
        if len(i)>4:
            if not i == ipInput:
                print '[+] A records from Robtex: ' + (i)
    if i=='':
        print '[-] This IP does not resolve to a domain'
    
    
def ipvoid(ipInput):                
    proxy = urllib2.ProxyHandler()
    opener = urllib2.build_opener(proxy)
    response = opener.open("http://ipvoid.com/scan/" + ipInput)
    content = response.read()
    contentString = str(content)
    
    rpderr = re.compile('An\sError\soccurred', re.IGNORECASE)
    rpdFinderr = re.findall(rpderr,contentString)
    # print content2String
    if "ERROR" in str(rpdFinderr):
        ipvoidErr = True
    else:
        ipvoidErr = False
    if ipvoidErr == False:
        rpd2 = re.compile('Detected\<\/font\>\<\/td..td..a.rel..nofollow..href.\"(.{6,70})\"\stitle\=\"View', re.IGNORECASE)
        rpdFind2 = re.findall(rpd2,contentString)
        rpdSorted2=sorted(rpdFind2)
    
        rpd3 = re.compile('ISP\<\/td\>\<td\>(.+)\<\/td\>', re.IGNORECASE)
        rpdFind3 = re.findall(rpd3,contentString)
        rpdSorted3=sorted(rpdFind3)
    
        rpd4 = re.compile('Country\sCode.+flag\"\s\/\>\s(.+)\<\/td\>', re.IGNORECASE)
        rpdFind4 = re.findall(rpd4,contentString)
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
        contentString = str(page)
        
        rpd2 = re.compile('Detected\<\/font\>\<\/td..td..a.rel..nofollow..href.\"(.{6,70})\"\stitle\=\"View', re.IGNORECASE)
        rpdFind2 = re.findall(rpd2,contentString)
        rpdSorted2=sorted(rpdFind2)
    
        rpd3 = re.compile('ISP\<\/td\>\<td\>(.+)\<\/td\>', re.IGNORECASE)
        rpdFind3 = re.findall(rpd3,contentString)
        rpdSorted3=sorted(rpdFind3)
    
        rpd4 = re.compile('Country\sCode.+flag\"\s\/\>\s(.+)\<\/td\>', re.IGNORECASE)
        rpdFind4 = re.findall(rpd4,contentString)
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
    proxy = urllib2.ProxyHandler()
    opener = urllib2.build_opener(proxy)
    response = opener.open("http://www.fortiguard.com/ip_rep/index.php?data=" + ipInput + "&lookup=Lookup")
    content = response.read()
    contentString = str(content)
    
    rpd = re.compile('Category:\s(.+)\<\/h3\>\s\<a', re.IGNORECASE)
    rpdFind = re.findall(rpd,contentString)
    rpdSorted=sorted(rpdFind)
    
    #print content3String
    m=''
    for m in rpdSorted:
        print ('[+] FortiGuard URL Categorization: '+ m)
    if m =='':
        print ('[-] Unable to connect to FortiGuard.com')

def unshortunURL(url):
    proxy = urllib2.ProxyHandler()
    opener = urllib2.build_opener(proxy)
    response = opener.open("http://unshort.me/index.php?r=" + url)
    content = response.read()
    contentString = str(content)
    
    rpd = re.compile('result\"\>\s\<a\shref\=\".+\>(.+)\<\/a\>\s', re.IGNORECASE)
    rpdFind = re.findall(rpd,contentString)
    rpdSorted=sorted(rpdFind)
    
    # print content3String

    m=''
    for m in rpdSorted:
        if url not in m:
            print ('[+] ' + url + ' redirects to: ' + m)
        else:
            print ('[-] ' + url + ' is not a recognized shortened URL.')
def urlvoid(url):                
    proxy = urllib2.ProxyHandler()
    opener = urllib2.build_opener(proxy)
    response = opener.open("http://urlvoid.com/scan/" + url)
    content = response.read()
    contentString = str(content)
    
    rpderr = re.compile('An\sError\soccurred', re.IGNORECASE)
    rpdFinderr = re.findall(rpderr,contentString)
    # print contentString
    if "ERROR" in str(rpdFinderr):
        ipvoidErr = True
    else:
        ipvoidErr = False
    if ipvoidErr == False:
        
        rpd1 = re.compile('(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}).+Scan\swith\s', re.IGNORECASE)
        rpdFind1 = re.findall(rpd1,contentString)
        rpdSorted1=sorted(rpdFind1) 
        
        rpd2 = re.compile('DETECTED.{25,40}href\=\"(.{10,50})\"\stitle', re.IGNORECASE)
        rpdFind2 = re.findall(rpd2,contentString)
        rpdSorted2=sorted(rpdFind2)   

        rpd3 = re.compile('latitude\s\/\slongitude.+\<td\>(.+)\<\/td\>', re.IGNORECASE)
        rpdFind3 = re.findall(rpd3,contentString)
        rpdSorted3=sorted(rpdFind3)
        
        rpd4 = re.compile('alt\=\"flag\".+\>(.+)\<\/td\>', re.IGNORECASE)
        rpdFind4 = re.findall(rpd4,contentString)
        rpdSorted4=sorted(rpdFind4)
        
        rpd5 = re.compile('Domain\s1st\sRegistered.+\<td\>(.+)\<\/td\>', re.IGNORECASE)
        rpdFind5 = re.findall(rpd5,contentString)
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
        contentString = str(page)
        #print contentString
        rpd1 = re.compile('(\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}).+Scan\swith\s', re.IGNORECASE)
        rpdFind1 = re.findall(rpd1,contentString)
        rpdSorted1=sorted(rpdFind1) 
        
        rpd2 = re.compile('DETECTED.{25,40}href\=\"(.{10,50})\"\stitle', re.IGNORECASE)
        rpdFind2 = re.findall(rpd2,contentString)
        rpdSorted2=sorted(rpdFind2)   

        rpd3 = re.compile('latitude\s\/\slongitude.+\<td\>(.+)\<\/td\>', re.IGNORECASE)
        rpdFind3 = re.findall(rpd3,contentString)
        rpdSorted3=sorted(rpdFind3)
        
        rpd4 = re.compile('alt\=\"flag\".+\>(.+)\<\/td\>', re.IGNORECASE)
        rpdFind4 = re.findall(rpd4,contentString)
        rpdSorted4=sorted(rpdFind4)
        
        rpd5 = re.compile('Domain\s1st\sRegistered.+\<td\>(.+)\<\/td\>', re.IGNORECASE)
        rpdFind5 = re.findall(rpd5,contentString)
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
    url = "http://labs.alienvault.com/labs/index.php/projects/open-source-ip-reputation-portal/information-about-ip/?ip=" + ipInput   
    proxy = urllib2.ProxyHandler()
    opener = urllib2.build_opener(proxy)
    response = opener.open("http://labs.alienvault.com/labs/index.php/projects/open-source-ip-reputation-portal/information-about-ip/?ip=" + ipInput)
    content = response.read()
    contentString = str(content)
    
    rpd = re.compile('.*IP not found.*')
    rpdFind = re.findall(rpd,contentString)

    if not rpdFind:
        print ('[+] IP is listed in AlienVault IP reputation database at ' + url)
    else:
        print ('[-] IP is not listed in AlienVault IP reputation database')

def md5Hash(md5):
    # Set proxy based on system default
    proxy = urllib2.ProxyHandler()
    opener = urllib2.build_opener(proxy)
    
    # Connect to threatexpert and check if hash is listed 
    url = "http://www.threatexpert.com/report.aspx?md5=" + md5
    response = opener.open(url)
    content = response.read()
    contentString = str(content)
    rpd = re.compile('Submission\sreceived.\s(.+)\<\/li\>')
    rpdFind = re.findall(rpd,contentString)

    # Connect to minotaur and check if hash is listed 
    url1 = "http://minotauranalysis.com/search.aspx?q=" + md5 
    response1 = opener.open(url1)
    content1 = response1.read()
    contentString1 = str(content1)
    rpd1 = re.compile('Date\sSubmitted.\<\/td\>\<td\>(.{12,25})\<\/td\>')
    rpdFind1 = re.findall(rpd1,contentString1)

    # Connect to virustotal and check if hash is listed 
    url2 = "https://www.virustotal.com/en/file/" + md5 + '/analysis/'
    response2 = opener.open(url2)
    content2 = response2.read()
    contentString2 = str(content2)
    rpd2 = re.compile('(\d{4}\-\d{2}\-\d{1,2}\s.+UTC)\s\-\sVirusTotal')
    rpdFind2 = re.findall(rpd2,contentString2)

    # Connect to vxvault and check if hash is listed 
    url3 = "http://vxvault.siri-urz.net/ViriList.php?MD5=" + md5
    response3 = opener.open(url3)
    content3 = response3.read()
    contentString3 = str(content3)      
    rpd3 = re.compile('\d{4}\-\d{2}\-\d{2}')
    rpdFind3 = re.findall(rpd3,contentString3)
    
    # print results of hash findings
    if rpdFind:
        print ('[+] MD5 last scanned on ' + str(rpdFind)[2:-2] + ' at ' + url)
    else:
        print ('[-] MD5 Not Found ThreatExpert')
 
    if rpdFind1:
        print ('[+] MD5 last scanned on ' + str(rpdFind1)[2:-2] + ' at ' + url1)
    else:
        print ('[-] MD5 Not Found on Minotaur')    
    
    if rpdFind2:
        print ('[+] MD5 last scanned on ' + str(rpdFind2)[2:-2] + ' at ' + url2)
    else:
        print ('[-] MD5 Not Found on VirusTotal')   
    
    if rpdFind3:
        print ('[+] MD5 last scanned on ' + str(rpdFind3[0]) + ' at ' + url3)
    else:
        print ('[-] MD5 Not Found on VxVault')   
# Determine if a target is an IP, URL, or HASH, then run the appropriate toolset          
def targetID(input):
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
            
    rpd9 = re.compile('[a-fA-F0-9]{32}', re.IGNORECASE)
    rpdFind9 = re.findall(rpd9,input)
    rpdSorted9=sorted(rpdFind9)
    rpdSorted9=str(rpdSorted9)
    rpdSorted9=rpdSorted9[2:-2]
            
    if rpdSorted7 == input:
        print '--------------------------------'
        print '[*] ' + input + ' is an IP. ' 
        print '[*] Running IP toolset'
        ipInput = input
        robtex(ipInput)
        ipvoid(ipInput)
        fortiURL(ipInput)
        alienvault(ipInput)
            
    elif rpdSorted9 == input:
        print '--------------------------------'
        print '[*] ' + input + ' is an MD5 Hash. ' 
        print '[*] Running MD5 Hash Toolset'
        md5 = input
        md5Hash(md5) 
    else:
        print '--------------------------------'
        print '[*] ' + input + ' is a URL.  '
        print '[*] Running URL toolset'
        urlInput = input
        unshortunURL(urlInput)
        urlvoid(urlInput)
        fortiURL(urlInput)  

if __name__ == "__main__":
    main()
