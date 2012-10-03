#!/usr/bin/env python
import sys
import os
import re
import datetime
import subprocess
import shlex
import time
from time import localtime, strftime
import smtplib
from email.MIMEText import MIMEText

# CONFIGURATION:
# where you want log files, temp files, etc to live
rootdir = "/home/scanner/nmap_vs_nagios"
# root directory where your nagios configs live
nagios_conf_dir = "/usr/local/nagios/etc/objects/"
results = "%s/scan_results" % (rootdir)
# your nmap command
nmap_command = "nmap -sS -P0 -T4 -iL %s/subnets.txt -p 22 -oG %s" % (rootdir, results)
# your mail settings
mailhost = "localhost"
mailfrom = "scanner@machine.com"
mailto = ['user1@machine.com','user2@machine.com','user3@machine.com','user4@machine.com']
# set this to False if you don't want debug.log created
debug = True
logfile = "%s/debug.log" % (rootdir)
# a local copy of the results
final_output = "%s/last_results.txt" % (rootdir)
# END CONFIGURATION

# you can use excluded to set up lists of IPs we don't want to hear about, see EXAMPLE below
#sys.path.append(rootdir + "/lib")
#import excludes

# email a report
def mailrpt(message):
	msg = MIMEText(message)
	msg["Subject"] = "Report: nmap vs nagios"
	msg["From"] = mailfrom
	msg['To'] = ', '.join( mailto )
	server = smtplib.SMTP(mailhost)
	server.sendmail(mailfrom, mailto, msg.as_string())
	server.quit()

# what debug = True does
def degbu(msg):
  if debug == True:
	#print "DEBUG: %s" % msg
	recdate = strftime("%a, %d %b %Y %H:%M:%S %Z", localtime())
	log = open(logfile, 'a')
	content = "%s: %s\n" % (recdate,msg)
	log.write(content)
	log.close()

# walk nagios_conf_dir, and look for 'address' in any .cfg file
def get_nagios_ips(confdir):
	conflist = []
	for root, subFolders, files in os.walk(confdir):
        	for file in files:
                	r = re.search(".cfg$", os.path.join(root,file))
                	if r != None:
                        	conflist.append(os.path.join(root,file))
	nagios_ips = []
	for c in conflist:
        	f = open(c)
        	data = f.read()
        	f.close()
        	lines = data.split("\n")
        	for line in lines: 
                	r = re.search("address", line)
                	if r != None:
                        	nagios_ips.append(line.split("address")[1].strip())
	return nagios_ips

# execute a command
def runcomm(command_line):
	start = datetime.datetime.now()
	process = subprocess.Popen(shlex.split(command_line), stdout = subprocess.PIPE, stderr = subprocess.PIPE)
	out, error = process.communicate()
	return out

# clean up nmap data to generate a list of IPs
def parse_nmap(results):
	f = open(results)
	data = f.read()
	f.close()
	nr = []
	lines = data.split("\n")
	for line in lines:
	   if line != "":
        	r = re.search("/open/", line)
        	if r != None:
                     nr.append(line.split()[1])
	return nr

# compare two lists, return unique entries in target
def clean_ips(source,target):
	for s in source:
		if s in target:
                       	target.remove(s)
	return target

# do a scan and create a list of IPs from that scan
degbu("Scanning IPs...")
runcomm(nmap_command)

# read in the greppable formatted output and produce a list of IPs
degbu("Parsing scan results...")
scan_ips = parse_nmap(results)

# get a list of all IPs in nagios configs
degbu("Collecting Nagios IPs....")
nagios_ips = get_nagios_ips(nagios_conf_dir)

# EXAMPLE: remove any load-balancer IPs from the list
# degbu("Removing LB IPs from list...")
# scan_ips = clean_ips(excludes.lbips, scan_ips)

# remove IPs present in nagios from the list
degbu("Removing nagios IPs from list...")
scan_ips = clean_ips(nagios_ips, scan_ips)

# generate the results file and report email
os.remove(final_output)
mailmsg = "IPs not in nagios: %s\n \n" % (strftime("%a, %d %b %Y %H:%M:%S %Z", localtime()))
degbu("Writing final_output...")
rf = open (final_output, 'a')
for ips in scan_ips:
	mailmsg += ips + "\n"
        rf.write(ips + "\n")
rf.close()
mailmsg += " \nTotal: %s" % (str(len(scan_ips)))
degbu("Sending mail report...")
mailrpt(mailmsg)
sys.exit()
