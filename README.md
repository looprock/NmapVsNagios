NmapVsNagios
============

Compare nmap scans with nagios configs

nmap vs nagios is a python script intended to do a scan of network(s) and compare with ipaddress entries found in nagios configurations. It generates a list of IPs found in the scan that aren't present in nagios and emails a report with that information. It's intended to run from cron at regular intervals. 

1. create a 'rootdir' where you want logs and output to go
2. configure your nagios conf dir
3. tune nmap if you want to, but don't change anything after -oG!
4. under that directory, create subnets.txt with all the ips/networks you want to scan and compare
5. configure your mail settings
6. add nmap_vs_nagios.py to your crontab (ok, maybe test it first..)

Should be good to go after that.
