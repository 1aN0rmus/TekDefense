#!/usr/bin/python
 
import os
 
# MASTIFF Autorun
# @TekDefense
# www.TekDefense.com
# Quick script to autorun samples from maltrieve to MASTIFF
 
malwarePath = '/tmp/malware/'
 
for r, d, f in os.walk(malwarePath):
  for files in f:
		malware = malwarePath + files
		print malware
		os.system ('mas.py' + ' ' + malware) 
