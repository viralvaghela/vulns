# vulns
list of vulns 
## 1. Web & API Vulnerabilities
### Easy
SQL Injection (SQLi) – Basic

Cross-Site Scripting (XSS) – Reflected

Cross-Site Scripting (XSS) – Stored

Cross-Site Scripting (XSS) – DOM-based

Cross-Site Request Forgery (CSRF)

Open Redirect

HTTP Header Injection

HTML Injection

Host Header Injection

Directory Listing / Directory Traversal

Information Disclosure via Comments / Error Messages

Missing Security Headers (CSP, HSTS, X-Frame-Options, etc.)

Unrestricted File Upload

Insecure Direct Object Reference (IDOR)

Weak Password Policy

Predictable Resource Locations / Files

CORS Misconfiguration – Basic

HTTP Verb Tampering

API Rate Limiting Bypass

Lack of Input Validation

Authentication Bypass via Parameter Tampering

Enumeration via Response Messages

### Medium
Blind SQL Injection (Boolean / Time-based)

NoSQL Injection

LDAP Injection

Server-Side Request Forgery (SSRF) – Basic

Broken Authentication & Session Management

JWT Attacks – None Algorithm / Weak Secret

GraphQL Vulnerabilities – Introspection Enabled

Mass Assignment

Prototype Pollution – Client-Side

XML External Entity (XXE) Injection

Template Injection (SSTI) – Basic

Business Logic Flaws (Price Manipulation, Order Skipping)

Path Confusion / Route Traversal in APIs

Caching Vulnerabilities – Cache Poisoning, Cache Deception

CORS Misconfiguration – Advanced (preflight bypass)

Privilege Escalation via Parameter Tampering

WebSocket Authentication Bypass

API Key Exposure in Frontend Code

HTTP Parameter Pollution (HPP)

OAuth Misconfiguration

SAML Misconfiguration

Race Condition – Basic (Double Spend, Concurrent Updates)

Clickjacking (UI Redress)

### Hard
Remote Code Execution (RCE)

Advanced SSRF → Internal Pivoting

NoSQL Injection → RCE Chaining

DNS Rebinding

Subdomain Takeover

Advanced Template Injection (SSTI → RCE)

Advanced CORS Exploitation – JSONP Abuse

API Injection via Webhooks / Callbacks

Chained Exploits (IDOR → Priv Esc → RCE)

Client-Side Prototype Pollution → Supply Chain Compromise

DOM Clobbering

Advanced GraphQL Attacks – Query Batching DoS

Cache Poisoned DoS (CPDoS)

Advanced Business Logic Race Conditions

HTTP/2 Cleartext (H2C) Smuggling

HTTP Request Smuggling / Desync

Server-Side Rendering (SSR) Vulnerabilities

Web Cache Deception → Sensitive Data Theft

JSON Deserialization RCE

Advanced WebSocket Injection

Supply Chain Attack – Malicious JS/NPM Dependency

## 2. Network & Infrastructure Vulnerabilities
### Easy
Open Ports / Service Enumeration

Default Credentials on Services / Devices

Unencrypted Protocols (HTTP, FTP, Telnet, SNMPv1)

Banner Grabbing / Version Disclosure

ICMP Ping Sweeps

Anonymous FTP Access

Guest SMB Shares

SNMP Misconfiguration

Exposed Admin Interfaces

Misconfigured Firewall Rules (Overly Permissive)

### Medium
SMB Relay Attacks

NTLM Relay

LLMNR / NBT-NS Poisoning

Weak TLS/SSL Configuration (SSLv3, TLS 1.0, RC4)

ARP Spoofing / MITM

DHCP Spoofing

VPN Misconfiguration

Port Knocking Bypass

RDP Vulnerabilities (BlueKeep, Weak Creds)

Brute Force Attacks on Services

IPv6 Attacks (RA Flood, Fake DHCPv6)

DNS Cache Poisoning

Router ACL Bypass

Reverse Proxy Misconfigurations

### Hard
Zero-Day Network Exploits

BGP Hijacking

Advanced Pivoting / Tunneling (SOCKS, Chisel, SSH)

Remote Kernel Exploits

VLAN Hopping

SCADA / ICS Protocol Exploitation (Modbus, DNP3)

Wi-Fi Attacks (WPA2 Kr00k, WPA3 Dragonblood)

Network Protocol Downgrade Attacks

Advanced MITM – TLS Stripping, SSL Hijacking

Firewall Evasion & IDS Bypass

Out-of-Band Management Exploits (iLO, DRAC, IPMI)

DNS Rebinding in Internal Apps

DHCP Starvation Attacks

## 3. Cloud Security Vulnerabilities
### Easy
Publicly Accessible S3 Buckets / Azure Blob / GCP Storage

Exposed Cloud Credentials in Code

Overly Permissive IAM Roles / Policies

No MFA on Cloud Accounts

Security Group Misconfigurations (0.0.0.0/0)

Publicly Accessible RDS / DB Instances

Lack of Logging (CloudTrail, Stackdriver, Activity Logs disabled)

Default Service Account Permissions

### Medium
SSRF to Cloud Metadata Service (AWS, Azure, GCP)

IAM Privilege Escalation (Misconfigured Policies)

Cross-Account Role Assumption

KMS (Key Management Service) Misuse

API Gateway Misconfigurations

Insecure Serverless Functions (AWS Lambda, Azure Functions)

Exposed Kubernetes Dashboard

Unrestricted Egress from Cloud Resources

Storage Signed URL Abuse

CloudFormation / Terraform State File Exposure

Unrestricted SNS/SQS Topics

Cloud Asset Enumeration (Public AMIs, Disks)

### Hard
Chaining SSRF → Metadata → IAM Role Compromise

Kubernetes Privilege Escalation → Cluster Admin

Container Escape in Cloud Environments

Cross-Region / Cross-Account Data Exfiltration

Exploiting CI/CD in Cloud (CodeBuild, Cloud Functions)

Supply Chain Attack in Cloud Dependencies

Resource Abuse for Crypto Mining / Billing Manipulation

Cloud-Specific Zero-Days

Advanced API Privilege Escalation

Attacking Federated Identity (SSO / OIDC Misconfigurations)

Stealing OAuth Tokens from Cloud Integrations

Exploiting Serverless Cold Starts / Race Conditions
