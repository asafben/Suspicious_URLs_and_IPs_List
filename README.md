# Suspicious_URLs_and_IPs_List
A script that compiles a list of malicious and/or generally suspicious:  
1. Domain names (e.g. zvpprsensinaix.com for Banjori malware).  
2. URL (e.g. hXXp://109.162.38.120/harsh02.exe for known malicious executable).  
3. IP address (e.g. 185.130.5.231 for known attacker).  

It gathers its information from constantly updating, publicly available, repositories.  
Each '.py' under '/feeds' responsible for data mining of a different publicly available source.  
For each feed there is a classification of: list type (domain / IP) and threat type (malware, CnC, etc..).  

The project is based on code from [here](https://github.com/stamparm/maltrail).
