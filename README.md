# Master Vulnerability Learning Checklist

## 1. Web & API Vulnerabilities

### Easy
- [ ] SQL Injection (SQLi) – Basic
- [ ] Cross-Site Scripting (XSS) – Reflected
- [ ] Cross-Site Scripting (XSS) – Stored
- [ ] Cross-Site Scripting (XSS) – DOM-based
- [ ] Cross-Site Request Forgery (CSRF)
- [ ] Open Redirect
- [ ] HTTP Header Injection
- [ ] HTML Injection
- [ ] Host Header Injection
- [ ] Directory Listing / Directory Traversal
- [ ] Information Disclosure via Comments / Error Messages
- [ ] Missing Security Headers (CSP, HSTS, X-Frame-Options, etc.)
- [ ] Unrestricted File Upload
- [ ] Insecure Direct Object Reference (IDOR)
- [ ] Weak Password Policy
- [ ] Predictable Resource Locations / Files
- [ ] CORS Misconfiguration – Basic
- [ ] HTTP Verb Tampering
- [ ] API Rate Limiting Bypass
- [ ] Lack of Input Validation
- [ ] Authentication Bypass via Parameter Tampering
- [ ] Enumeration via Response Messages

### Medium
- [ ] Blind SQL Injection (Boolean / Time-based)
- [ ] NoSQL Injection
- [ ] LDAP Injection
- [ ] Server-Side Request Forgery (SSRF) – Basic
- [ ] Broken Authentication & Session Management
- [ ] JWT Attacks – None Algorithm / Weak Secret
- [ ] GraphQL Vulnerabilities – Introspection Enabled
- [ ] Mass Assignment
- [ ] Prototype Pollution – Client-Side
- [ ] XML External Entity (XXE) Injection
- [ ] Template Injection (SSTI) – Basic
- [ ] Business Logic Flaws (Price Manipulation, Order Skipping)
- [ ] Path Confusion / Route Traversal in APIs
- [ ] Caching Vulnerabilities – Cache Poisoning, Cache Deception
- [ ] CORS Misconfiguration – Advanced (preflight bypass)
- [ ] Privilege Escalation via Parameter Tampering
- [ ] WebSocket Authentication Bypass
- [ ] API Key Exposure in Frontend Code
- [ ] HTTP Parameter Pollution (HPP)
- [ ] OAuth Misconfiguration
- [ ] SAML Misconfiguration
- [ ] Race Condition – Basic (Double Spend, Concurrent Updates)
- [ ] Clickjacking (UI Redress)

### Hard
- [ ] Remote Code Execution (RCE)
- [ ] Advanced SSRF → Internal Pivoting
- [ ] NoSQL Injection → RCE Chaining
- [ ] DNS Rebinding
- [ ] Subdomain Takeover
- [ ] Advanced Template Injection (SSTI → RCE)
- [ ] Advanced CORS Exploitation – JSONP Abuse
- [ ] API Injection via Webhooks / Callbacks
- [ ] Chained Exploits (IDOR → Priv Esc → RCE)
- [ ] Client-Side Prototype Pollution → Supply Chain Compromise
- [ ] DOM Clobbering
- [ ] Advanced GraphQL Attacks – Query Batching DoS
- [ ] Cache Poisoned DoS (CPDoS)
- [ ] Advanced Business Logic Race Conditions
- [ ] HTTP/2 Cleartext (H2C) Smuggling
- [ ] HTTP Request Smuggling / Desync
- [ ] Server-Side Rendering (SSR) Vulnerabilities
- [ ] Web Cache Deception → Sensitive Data Theft
- [ ] JSON Deserialization RCE
- [ ] Advanced WebSocket Injection
- [ ] Supply Chain Attack – Malicious JS/NPM Dependency


## 2. Network & Infrastructure Vulnerabilities

### Easy
- [ ] Open Ports / Service Enumeration
- [ ] Default Credentials on Services / Devices
- [ ] Unencrypted Protocols (HTTP, FTP, Telnet, SNMPv1)
- [ ] Banner Grabbing / Version Disclosure
- [ ] ICMP Ping Sweeps
- [ ] Anonymous FTP Access
- [ ] Guest SMB Shares
- [ ] SNMP Misconfiguration
- [ ] Exposed Admin Interfaces
- [ ] Misconfigured Firewall Rules (Overly Permissive)

### Medium
- [ ] SMB Relay Attacks
- [ ] NTLM Relay
- [ ] LLMNR / NBT-NS Poisoning
- [ ] Weak TLS/SSL Configuration (SSLv3, TLS 1.0, RC4)
- [ ] ARP Spoofing / MITM
- [ ] DHCP Spoofing
- [ ] VPN Misconfiguration
- [ ] Port Knocking Bypass
- [ ] RDP Vulnerabilities (BlueKeep, Weak Creds)
- [ ] Brute Force Attacks on Services
- [ ] IPv6 Attacks (RA Flood, Fake DHCPv6)
- [ ] DNS Cache Poisoning
- [ ] Router ACL Bypass
- [ ] Reverse Proxy Misconfigurations

### Hard
- [ ] Zero-Day Network Exploits
- [ ] BGP Hijacking
- [ ] Advanced Pivoting / Tunneling (SOCKS, Chisel, SSH)
- [ ] Remote Kernel Exploits
- [ ] VLAN Hopping
- [ ] SCADA / ICS Protocol Exploitation (Modbus, DNP3)
- [ ] Wi-Fi Attacks (WPA2 Kr00k, WPA3 Dragonblood)
- [ ] Network Protocol Downgrade Attacks
- [ ] Advanced MITM – TLS Stripping, SSL Hijacking
- [ ] Firewall Evasion & IDS Bypass
- [ ] Out-of-Band Management Exploits (iLO, DRAC, IPMI)
- [ ] DNS Rebinding in Internal Apps
- [ ] DHCP Starvation Attacks


## 3. Cloud Security Vulnerabilities

### Easy
- [ ] Publicly Accessible S3 Buckets / Azure Blob / GCP Storage
- [ ] Exposed Cloud Credentials in Code
- [ ] Overly Permissive IAM Roles / Policies
- [ ] No MFA on Cloud Accounts
- [ ] Security Group Misconfigurations (0.0.0.0/0)
- [ ] Publicly Accessible RDS / DB Instances
- [ ] Lack of Logging (CloudTrail, Stackdriver, Activity Logs disabled)
- [ ] Default Service Account Permissions

### Medium
- [ ] SSRF to Cloud Metadata Service (AWS, Azure, GCP)
- [ ] IAM Privilege Escalation (Misconfigured Policies)
- [ ] Cross-Account Role Assumption
- [ ] KMS (Key Management Service) Misuse
- [ ] API Gateway Misconfigurations
- [ ] Insecure Serverless Functions (AWS Lambda, Azure Functions)
- [ ] Exposed Kubernetes Dashboard
- [ ] Unrestricted Egress from Cloud Resources
- [ ] Storage Signed URL Abuse
- [ ] CloudFormation / Terraform State File Exposure
- [ ] Unrestricted SNS/SQS Topics
- [ ] Cloud Asset Enumeration (Public AMIs, Disks)

### Hard
- [ ] Chaining SSRF → Metadata → IAM Role Compromise
- [ ] Kubernetes Privilege Escalation → Cluster Admin
- [ ] Container Escape in Cloud Environments
- [ ] Cross-Region / Cross-Account Data Exfiltration
- [ ] Exploiting CI/CD in Cloud (CodeBuild, Cloud Functions)
- [ ] Supply Chain Attack in Cloud Dependencies
- [ ] Resource Abuse for Crypto Mining / Billing Manipulation
- [ ] Cloud-Specific Zero-Days
- [ ] Advanced API Privilege Escalation
- [ ] Attacking Federated Identity (SSO / OIDC Misconfigurations)
- [ ] Stealing OAuth Tokens from Cloud Integrations
- [ ] Exploiting Serverless Cold Starts / Race Conditions

## THM 
# Level 1 - Intro
- [ ] OpenVPN  https://tryhackme.com/room/openvpn
- [ ] Welcome  https://tryhackme.com/jr/welcome
- [ ] Intro to Researching  https://tryhackme.com/room/introtoresearch
- [ ] Learn Linux  https://tryhackme.com/room/zthlinux
- [ ] Crash Course Pentesting  https://tryhackme.com/room/ccpentesting
Introductory CTFs to get your feet wet
- [ ] Google Dorking  https://tryhackme.com/room/googledorking
- [ ] OHsint  https://tryhackme.com/room/ohsint
- [ ] Shodan.io  https://tryhackme.com/room/shodan
# Level 2 - Tooling
- [ ] Tmux  https://tryhackme.com/room/rptmux
- [ ] Nmap  https://tryhackme.com/room/rpnmap
- [ ] Web Scanning  https://tryhackme.com/room/rpwebscanning
- [ ] Sublist3r  https://tryhackme.com/room/rpsublist3r
- [ ] Metasploit  https://tryhackme.com/room/rpmetasploit
- [ ] Hydra  https://tryhackme.com/room/hydra
- [ ] Linux Privesc  https://tryhackme.com/room/linuxprivesc
- [ ] Web Scanning  https://tryhackme.com/room/rpwebscanning
More introductory CTFs
- [ ] Vulnversity -  https://tryhackme.com/room/vulnversity
- [ ] Blue -  https://tryhackme.com/room/blue
- [ ] Simple CTF  https://tryhackme.com/room/easyctf
- [ ] Bounty Hacker  https://tryhackme.com/room/cowboyhacker
# Level 3 - Crypto & Hashes with CTF practice
- [ ] Crack the hash  https://tryhackme.com/room/crackthehash
- [ ] Agent Sudo  https://tryhackme.com/room/agentsudoctf
- [ ] The Cod Caper  https://tryhackme.com/room/thecodcaper
- [ ] Ice  https://tryhackme.com/room/ice
- [ ] Lazy Admin  https://tryhackme.com/room/lazyadmin
- [ ] Basic Pentesting  https://tryhackme.com/room/basicpentestingjt
# Level 4 - Web
- [ ] OWASP top 10  https://tryhackme.com/room/owasptop10
- [ ] Inclusion  https://tryhackme.com/room/inclusion
- [ ] Injection  https://tryhackme.com/room/injection
- [ ] Vulnversity  https://tryhackme.com/room/vulnversity
- [ ] Basic Pentesting  https://tryhackme.com/room/basicpentestingjt
- [ ] Juiceshop  https://tryhackme.com/room/owaspjuiceshop
- [ ] Ignite  https://tryhackme.com/room/ignite
- [ ] Overpass  https://tryhackme.com/room/overpass
- [ ] Year of the Rabbit  https://tryhackme.com/room/yearoftherabbit
- [ ] DevelPy  https://tryhackme.com/room/bsidesgtdevelpy
- [ ] Jack of all trades  https://tryhackme.com/room/jackofalltrades
- [ ] Bolt  https://tryhackme.com/room/bolt
# Level 5 - Reverse Engineering
- [ ] Intro to x86 64  https://tryhackme.com/room/introtox8664
- [ ] CC Ghidra  https://tryhackme.com/room/ccghidra
- [ ] CC Radare2  https://tryhackme.com/room/ccradare2
- [ ] CC Steganography  https://tryhackme.com/room/ccstego
- [ ] Reverse Engineering  https://tryhackme.com/room/reverseengineering
- [ ] Reversing ELF  https://tryhackme.com/room/reverselfiles
- [ ] Dumping Router Firmware  https://tryhackme.com/room/rfirmware
# Level 6 - PrivEsc
- [ ] Sudo Security Bypass  https://tryhackme.com/room/sudovulnsbypass
- [ ] Sudo Buffer Overflow  https://tryhackme.com/room/sudovulnsbof
- [ ] Windows Privesc Arena  https://tryhackme.com/room/windowsprivescarena
- [ ] Linux Privesc Arena  https://tryhackme.com/room/linuxprivescarena
- [ ] Windows Privesc  https://tryhackme.com/room/windows10privesc
- [ ] Blaster  https://tryhackme.com/room/blaster
- [ ] Ignite  https://tryhackme.com/room/ignite
- [ ] Kenobi  https://tryhackme.com/room/kenobi
- [ ] Capture the flag  https://tryhackme.com/room/c4ptur3th3fl4g
- [ ] Pickle Rick  https://tryhackme.com/room/picklerick
# Level 7 - CTF practice
- [ ] Post Exploitation Basics  https://tryhackme.com/room/postexploit
- [ ] Smag Grotto  https://tryhackme.com/room/smaggrotto
- [ ] Inclusion  https://tryhackme.com/room/inclusion
- [ ] Dogcat  https://tryhackme.com/room/dogcat
- [ ] LFI basics  https://tryhackme.com/room/lfibasics
- [ ] Buffer Overflow Prep  https://tryhackme.com/room/bufferoverflowprep
- [ ] Overpass  https://tryhackme.com/room/overpass
- [ ] Break out the cage  https://tryhackme.com/room/breakoutthecage1
- [ ] Lian Yu  https://tryhackme.com/room/lianyu
 
      
