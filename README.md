# Do not attempt to violate the law with anything contained here.
> You shall not misuse the information to gain unauthorised access. <br/>
> This tool is related to Computer Security and do not promote hacking / cracking
<hr/>

### SMB EternalBlue and DoublePulsar exploit scanner tool made with GoLang
### MS17-010 vulnerabilities:
* CVE-2017-0143
* CVE-2017-0144
* CVE-2017-0145
* CVE-2017-0146
* CVE-2017-0147
* CVE-2017-0148.
<hr/>

### [!] Scaner can be detected by antivirus software [!]

C:\Users\user\Desktop> .\scanner.exe -h

Usage of C:\Users\user\Desktop\scanner.exe: <br/>
  -file string <br/>
        File with list of targets to scan. Each address or netmask on new line. <br/>
  -ip string <br/>
        IP address <br/>
  -net string <br/>
        IP network address. Example: 10.0.1.0/24 <br/>
  -out string <br/>
        Output file with results of scan in CSV format. Example: results.csv <br/>
  -verbose <br/>
        Verbose output <br/>
  -workers int <br/>
        Count of concurrent workers. (default 200) <br/>
<hr/>

### Some examples: 
* >scanner.exe -workers 1000 -file ips.txt -out exp.txt <br/>
* >go run wannacry_scaner.go --help <br/>
