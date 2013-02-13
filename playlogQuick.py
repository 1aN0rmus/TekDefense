#!/usr/bin/python

import re, os

print '''
  ____  _             _              ___        _      _    
 |  _ \| | __ _ _   _| | ___   __ _ / _ \ _   _(_) ___| | __
 | |_) | |/ _` | | | | |/ _ \ / _` | | | | | | | |/ __| |/ /
 |  __/| | (_| | |_| | | (_) | (_| | |_| | |_| | | (__|   < 
 |_|   |_|\__,_|\__, |_|\___/ \__, |\__\_\\__,_|_|\___|_|\_\
                |___/         |___/                                                                           
Author: Ian Ahl, 1aN0rmus@TekDefense.com
Created: 02/12/2013
'''

# variables for the kippo logs, if your path is not the default from honeydrive, modify logPath. 
# if your log files are not named kippo.log or kippor.log.x please modify logPre.
logPre = 'kippo.log'
logPath = '/opt/kippo/log/'
outputFile = '/opt/kippo/log/attacklog.txt'
reSearch = 'SSHChannel\ssession.+\,(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\s(.+)'
reCMD = '\,(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]\sCMD\:(.+)'
#reOut = 'Command\sfound\:\s(.+)'
sessionList = []

# open up the directory found in the logPath variable to find any files that start with the prefix from variable logPre.
# Opens each of those logfiles and uses regex to find to find the passwords and add them to a list.
for r, d, f in os.walk(logPath):
    for files in f:
        if files.startswith(logPre):
            #print files
            logFile = logPath + files
            #print logFile
            lines = open(logFile,'r').readlines()
            for i in lines:
                searchSession = re.search(reSearch,i)
                if searchSession is not None:
                    sessionList.append(searchSession.group())
# Removing duplicate entries with the set function.
# passwordList = list(set(passwordList))                   
# outputting results to the file defined in the outputFile variable.
# output = open(outputFile, 'w')
for i in sessionList:
    searchCMD = re.search(reCMD,i)
    #searchOutput = re.search(reOut,i)
    if searchCMD is not None:
        print (searchCMD.group(1) + '@honeypot#' + searchCMD.group(2))
    #elif searchOutput is not None:
    #    print(searchOutput.group(1))
    #else:
    #    print(i)
    # output.write(i + '\n')
# print 'Wordlist has been archived to ' + outputFile
    
           
            
            

            
        

